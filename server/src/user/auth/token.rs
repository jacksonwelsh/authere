use crate::db::DbEntity;
use crate::errors::AppError;
use crate::settings::{DEFAULT_SESSION_EXPIRY_SECONDS, session_expiry_seconds};

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use ed25519_dalek::{SigningKey, pkcs8::EncodePrivateKey};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{Connection, FromRow, SqliteConnection, query};
use utoipa::ToSchema;
use uuid::Uuid;

/// Access token lifetime in seconds (15 minutes)
pub const ACCESS_TOKEN_LIFETIME: i64 = 15 * 60;
/// Compatibility constant for the default session lifetime (7 days). New logins
/// load their absolute lifetime from the `session_expiry_seconds` setting.
pub const REFRESH_TOKEN_LIFETIME: i64 = DEFAULT_SESSION_EXPIRY_SECONDS;

const TOKEN_ISSUER: &str = "authere";
const TOKEN_AUDIENCE: &str = "authere";

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (user ID)
    pub sub: String,
    /// Issuer
    pub iss: String,
    /// Audience
    pub aud: String,
    /// User's roles
    pub roles: Vec<String>,
    /// Expiration time (Unix timestamp)
    pub exp: i64,
    /// Issued at (Unix timestamp)
    pub iat: i64,
    /// JWT ID (unique identifier for this token)
    pub jti: String,
    /// Token type: "access" or "refresh"
    pub typ: String,
    /// Absolute deadline set at login and preserved across refreshes.
    #[serde(default)]
    pub session_exp: Option<i64>,
    /// User session generation; absent on pre-upgrade tokens.
    #[serde(default)]
    pub session_version: Option<i64>,
    /// Time of the password/MFA authentication, preserved when refreshing.
    #[serde(default)]
    pub auth_time: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    /// Access-token lifetime in seconds.
    pub expires_in: i64,
    /// Refresh-token lifetime in seconds, reflecting the configured
    /// `session_expiry_seconds` setting at issue time.
    pub refresh_expires_in: i64,
    pub token_type: String,
}

#[derive(Debug, FromRow)]
pub struct RefreshTokenRecord {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub expires_at: i64,
    pub created_at: i64,
    pub revoked_at: Option<i64>,
}

// ============================================================================
// Key Encryption
// ============================================================================

/// Returns the 32-byte key-encryption key from AUTHERE_KEY_SECRET (hex-encoded).
fn get_kek() -> Result<[u8; 32], AppError> {
    let secret = std::env::var("AUTHERE_KEY_SECRET").map_err(|_| {
        AppError::InternalError(
            "AUTHERE_KEY_SECRET environment variable is required (32 random bytes, hex-encoded)"
                .to_string(),
        )
    })?;
    let bytes = hex::decode(secret.trim()).map_err(|_| {
        AppError::InternalError(
            "AUTHERE_KEY_SECRET must be hex-encoded (64 hex characters = 32 bytes)".to_string(),
        )
    })?;
    bytes.try_into().map_err(|_| {
        AppError::InternalError(
            "AUTHERE_KEY_SECRET must be exactly 32 bytes (64 hex characters)".to_string(),
        )
    })
}

fn encrypt_private_key(
    key_bytes: &[u8; 32],
    kek: &[u8; 32],
) -> Result<(Vec<u8>, [u8; 12]), AppError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(kek));
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), key_bytes.as_slice())
        .map_err(|e| AppError::InternalError(format!("Key encryption failed: {e}")))?;
    Ok((ciphertext, nonce_bytes))
}

fn decrypt_private_key(
    ciphertext: &[u8],
    nonce: &[u8; 12],
    kek: &[u8; 32],
) -> Result<[u8; 32], AppError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(kek));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| {
            AppError::InternalError("Key decryption failed — check AUTHERE_KEY_SECRET".to_string())
        })?;
    plaintext
        .try_into()
        .map_err(|_| AppError::InternalError("Decrypted key has invalid length".to_string()))
}

// ============================================================================
// Key Management
// ============================================================================

fn generate_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

/// Initializes the database with a signing key if not present. Returns Ok(true) if work was done,
/// Ok(false) otherwise.
pub async fn try_initialize(conn: &mut SqliteConnection) -> Result<bool, AppError> {
    let existing_key = query!("SELECT id FROM keys WHERE name = 'default'")
        .fetch_optional(&mut *conn)
        .await?;
    match existing_key {
        Some(_) => Ok(false),
        None => {
            initialize(conn).await?;
            Ok(true)
        }
    }
}

async fn initialize(conn: &mut SqliteConnection) -> Result<(), AppError> {
    let key = generate_key();
    let kek = get_kek()?;

    let id = Uuid::now_v7();
    let public_key = key.verifying_key().to_bytes();
    let private_key = key.to_bytes();
    let pubk_slice = &public_key[..];

    let (ciphertext, nonce) = encrypt_private_key(&private_key, &kek)?;
    let nonce_slice = &nonce[..];

    query!(
        "INSERT INTO keys (id, name, public_key, private_key, key_nonce) VALUES (?, 'default', ?, ?, ?)",
        id,
        pubk_slice,
        ciphertext,
        nonce_slice,
    )
    .execute(conn)
    .await?;

    Ok(())
}

/// Load the signing key from the database, decrypting it. Intended for startup caching.
pub async fn load_signing_key(conn: &mut SqliteConnection) -> Result<SigningKey, AppError> {
    let row = query!("SELECT private_key, key_nonce FROM keys WHERE name = 'default'")
        .fetch_one(&mut *conn)
        .await?;

    match row.key_nonce {
        None => {
            // Legacy plaintext key — re-encrypt in place on first use
            let kek = get_kek()?;
            let private_key: [u8; 32] = row
                .private_key
                .try_into()
                .map_err(|_| AppError::InternalError("Invalid key length".to_string()))?;
            let (ciphertext, nonce) = encrypt_private_key(&private_key, &kek)?;
            let nonce_slice = &nonce[..];
            query!(
                "UPDATE keys SET private_key = ?, key_nonce = ? WHERE name = 'default'",
                ciphertext,
                nonce_slice,
            )
            .execute(conn)
            .await?;
            Ok(SigningKey::from_bytes(&private_key))
        }
        Some(nonce_bytes) => {
            let kek = get_kek()?;
            let nonce: [u8; 12] = nonce_bytes
                .try_into()
                .map_err(|_| AppError::InternalError("Invalid nonce length".to_string()))?;
            let private_key = decrypt_private_key(&row.private_key, &nonce, &kek)?;
            Ok(SigningKey::from_bytes(&private_key))
        }
    }
}

fn current_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as i64
}

// ============================================================================
// Token Generation
// ============================================================================

/// Generates an access token for the given user using a cached signing key.
pub fn generate_access_token(
    user_id: Uuid,
    roles: Vec<String>,
    signing_key: &SigningKey,
) -> Result<String, AppError> {
    generate_access_token_for_session(
        user_id,
        roles,
        current_timestamp() + ACCESS_TOKEN_LIFETIME,
        Some(0),
        current_timestamp(),
        signing_key,
    )
}

fn generate_access_token_for_session(
    user_id: Uuid,
    roles: Vec<String>,
    session_expires_at: i64,
    session_version: Option<i64>,
    auth_time: i64,
    signing_key: &SigningKey,
) -> Result<String, AppError> {
    let now = current_timestamp();

    let claims = Claims {
        sub: user_id.to_string(),
        iss: TOKEN_ISSUER.to_string(),
        aud: TOKEN_AUDIENCE.to_string(),
        roles,
        exp: (now + ACCESS_TOKEN_LIFETIME).min(session_expires_at),
        iat: now,
        jti: Uuid::new_v4().to_string(),
        typ: "access".to_string(),
        session_exp: Some(session_expires_at),
        session_version,
        auth_time: Some(auth_time),
    };

    let header = Header::new(Algorithm::EdDSA);
    let pkcs8_der = signing_key
        .to_pkcs8_der()
        .map_err(|e| AppError::InternalError(format!("Failed to encode signing key: {e}")))?;
    let encoding_key = EncodingKey::from_ed_der(pkcs8_der.as_bytes());

    encode(&header, &claims, &encoding_key)
        .map_err(|e| AppError::InternalError(format!("Failed to encode JWT: {e}")))
}

/// Generates a refresh token with the given lifetime (seconds) and stores it in the database.
pub async fn generate_refresh_token(
    user_id: Uuid,
    lifetime_seconds: i64,
    signing_key: &SigningKey,
    conn: &mut SqliteConnection,
) -> Result<String, AppError> {
    let version = user_session_version(user_id, conn).await?;
    generate_refresh_token_for_session(
        user_id,
        current_timestamp() + lifetime_seconds,
        Some(version),
        current_timestamp(),
        signing_key,
        conn,
    )
    .await
}

async fn generate_refresh_token_for_session(
    user_id: Uuid,
    expires_at: i64,
    session_version: Option<i64>,
    auth_time: i64,
    signing_key: &SigningKey,
    conn: &mut SqliteConnection,
) -> Result<String, AppError> {
    let now = current_timestamp();

    let claims = Claims {
        sub: user_id.to_string(),
        iss: TOKEN_ISSUER.to_string(),
        aud: TOKEN_AUDIENCE.to_string(),
        roles: vec![], // Refresh tokens don't carry roles
        exp: expires_at,
        iat: now,
        jti: Uuid::new_v4().to_string(),
        typ: "refresh".to_string(),
        session_exp: Some(expires_at),
        session_version,
        auth_time: Some(auth_time),
    };

    let header = Header::new(Algorithm::EdDSA);
    let pkcs8_der = signing_key
        .to_pkcs8_der()
        .map_err(|e| AppError::InternalError(format!("Failed to encode signing key: {e}")))?;
    let encoding_key = EncodingKey::from_ed_der(pkcs8_der.as_bytes());

    let token = encode(&header, &claims, &encoding_key)
        .map_err(|e| AppError::InternalError(format!("Failed to encode JWT: {e}")))?;

    let token_hash = hash_token(&token);
    let id = Uuid::now_v7();

    query!(
        "INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
        id,
        user_id,
        token_hash,
        expires_at,
        now
    )
    .execute(conn)
    .await?;

    Ok(token)
}

/// Generates both access and refresh tokens for a user, honoring the configured
/// `session_expiry_seconds` setting for the refresh-token lifetime.
pub async fn generate_token_pair(
    user_id: Uuid,
    roles: Vec<String>,
    signing_key: &SigningKey,
    conn: &mut SqliteConnection,
) -> Result<TokenPair, AppError> {
    let expires_at = current_timestamp() + session_expiry_seconds(conn).await?;
    let version = user_session_version(user_id, conn).await?;
    generate_token_pair_for_session(
        user_id,
        roles,
        expires_at,
        Some(version),
        current_timestamp(),
        signing_key,
        conn,
    )
    .await
}

async fn generate_token_pair_for_session(
    user_id: Uuid,
    roles: Vec<String>,
    expires_at: i64,
    session_version: Option<i64>,
    auth_time: i64,
    signing_key: &SigningKey,
    conn: &mut SqliteConnection,
) -> Result<TokenPair, AppError> {
    let remaining = expires_at - current_timestamp();
    if remaining <= 0 {
        return Err(AppError::AuthenticationRequired);
    }
    let access_token = generate_access_token_for_session(
        user_id,
        roles,
        expires_at,
        session_version,
        auth_time,
        signing_key,
    )?;
    let refresh_token = generate_refresh_token_for_session(
        user_id,
        expires_at,
        session_version,
        auth_time,
        signing_key,
        conn,
    )
    .await?;

    Ok(TokenPair {
        access_token,
        refresh_token,
        expires_in: ACCESS_TOKEN_LIFETIME.min(remaining),
        refresh_expires_in: remaining,
        token_type: "Bearer".to_string(),
    })
}

// ============================================================================
// Token Verification
// ============================================================================

/// Verifies an access token and returns the claims.
/// Also checks user-level revocations so logout takes effect immediately.
pub async fn verify_access_token(
    token: &str,
    signing_key: &SigningKey,
    conn: &mut SqliteConnection,
) -> Result<Claims, AppError> {
    let verifying_key = signing_key.verifying_key();
    let decoding_key = DecodingKey::from_ed_der(&verifying_key.to_bytes());

    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.leeway = 0;
    validation.set_required_spec_claims(&["sub", "exp", "iat", "jti", "typ", "iss", "aud"]);
    validation.set_issuer(&[TOKEN_ISSUER]);
    validation.set_audience(&[TOKEN_AUDIENCE]);

    let mut token_data = decode::<Claims>(token, &decoding_key, &validation)
        .map_err(|_| AppError::AuthenticationRequired)?;

    if token_data.claims.typ != "access" {
        return Err(AppError::AuthenticationRequired);
    }
    if token_data.claims.exp <= current_timestamp()
        || token_data
            .claims
            .session_exp
            .is_some_and(|exp| exp <= current_timestamp())
    {
        return Err(AppError::AuthenticationRequired);
    }

    let user_id = Uuid::parse_str(&token_data.claims.sub)
        .map_err(|_| AppError::InternalError("Invalid user ID in token".to_string()))?;

    verify_user_session(
        user_id,
        token_data.claims.iat,
        token_data.claims.session_version,
        conn,
    )
    .await?;
    // Authorization decisions always use current database roles.
    let user = crate::user::User::get(user_id, conn)
        .await?
        .ok_or(AppError::AuthenticationRequired)?;
    token_data.claims.roles = user.get_roles(conn).await?;
    Ok(token_data.claims)
}

async fn user_session_version(user_id: Uuid, conn: &mut SqliteConnection) -> Result<i64, AppError> {
    sqlx::query_scalar::<_, i64>("SELECT token_version FROM users WHERE id = ? AND active = 1")
        .bind(user_id)
        .fetch_optional(conn)
        .await?
        .ok_or(AppError::AuthenticationRequired)
}

/// Shared revocation check for central, OIDC, and host-scoped forward sessions.
pub async fn verify_user_session(
    user_id: Uuid,
    issued_at: i64,
    session_version: Option<i64>,
    conn: &mut SqliteConnection,
) -> Result<(), AppError> {
    let current_version = user_session_version(user_id, conn).await?;
    if let Some(version) = session_version {
        return if version == current_version {
            Ok(())
        } else {
            Err(AppError::AuthenticationRequired)
        };
    }
    // No pre-upgrade credential may survive a generation-based revocation.
    if current_version != 0 {
        return Err(AppError::AuthenticationRequired);
    }
    let revocation = query!(
        "SELECT revoked_before FROM user_access_revocations WHERE user_id = ?",
        user_id
    )
    .fetch_optional(&mut *conn)
    .await?;

    if let Some(r) = revocation {
        if issued_at <= r.revoked_before {
            return Err(AppError::AuthenticationRequired);
        }
    }

    Ok(())
}

/// Atomically verifies a refresh token and revokes it in a single DB operation.
pub async fn verify_and_revoke_refresh_token(
    token: &str,
    signing_key: &SigningKey,
    conn: &mut SqliteConnection,
) -> Result<Uuid, AppError> {
    Ok(consume_refresh_token(token, signing_key, conn).await?.0)
}

async fn consume_refresh_token(
    token: &str,
    signing_key: &SigningKey,
    conn: &mut SqliteConnection,
) -> Result<(Uuid, Claims), AppError> {
    let verifying_key = signing_key.verifying_key();
    let decoding_key = DecodingKey::from_ed_der(&verifying_key.to_bytes());

    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.leeway = 0;
    validation.set_required_spec_claims(&["sub", "exp", "iat", "jti", "typ", "iss", "aud"]);
    validation.set_issuer(&[TOKEN_ISSUER]);
    validation.set_audience(&[TOKEN_AUDIENCE]);

    let mut token_data = decode::<Claims>(token, &decoding_key, &validation)
        .map_err(|_| AppError::AuthenticationRequired)?;

    if token_data.claims.typ != "refresh" {
        return Err(AppError::AuthenticationRequired);
    }
    let user_id =
        Uuid::parse_str(&token_data.claims.sub).map_err(|_| AppError::AuthenticationRequired)?;
    let version_before_verification = user_session_version(user_id, conn).await?;
    verify_user_session(
        user_id,
        token_data.claims.iat,
        token_data.claims.session_version,
        conn,
    )
    .await?;
    if token_data.claims.session_version.is_none() {
        token_data.claims.session_version = Some(version_before_verification);
    }

    let token_hash = hash_token(token);
    let now = current_timestamp();

    let result = query!(
        "UPDATE refresh_tokens SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL AND expires_at > ?",
        now,
        token_hash,
        now
    )
    .execute(&mut *conn)
    .await?;

    if result.rows_affected() != 1 {
        let exists = query!(
            "SELECT user_id as \"user_id: Uuid\" FROM refresh_tokens WHERE token_hash = ?",
            token_hash
        )
        .fetch_optional(&mut *conn)
        .await?;

        if let Some(row) = exists {
            let _ = revoke_all_user_tokens(row.user_id, conn).await;
        }

        return Err(AppError::AuthenticationRequired);
    }

    Ok((user_id, token_data.claims))
}

/// Rotate refresh credentials without extending the deadline established at login.
pub async fn rotate_token_pair(
    token: &str,
    signing_key: &SigningKey,
    conn: &mut SqliteConnection,
) -> Result<TokenPair, AppError> {
    let (user_id, claims) = consume_refresh_token(token, signing_key, conn).await?;
    let user = crate::user::User::get(user_id, conn)
        .await?
        .ok_or(AppError::AuthenticationRequired)?;
    let roles = user.get_roles(conn).await?;
    generate_token_pair_for_session(
        user_id,
        roles,
        claims.session_exp.unwrap_or(claims.exp).min(claims.exp),
        claims.session_version,
        claims.auth_time.unwrap_or(claims.iat),
        signing_key,
        conn,
    )
    .await
}

/// Browser requests can be in flight with the same cookie in multiple tabs.
/// Return the identical replacement for five seconds, rather than revoking the
/// user's sessions on a normal concurrent refresh. The JSON API remains strict.
pub async fn rotate_browser_token_pair(
    token: &str,
    signing_key: &SigningKey,
    conn: &mut SqliteConnection,
) -> Result<TokenPair, AppError> {
    // Serialize the consume / issue / save sequence across processes as well as
    // requests. A retry cannot observe a consumed token before its response exists.
    let mut tx = conn.begin_with("BEGIN IMMEDIATE").await?;
    let now = current_timestamp();
    let token_hash = hash_token(token);
    let retry = sqlx::query_as::<_, (Option<i64>, Option<Vec<u8>>)>(
        "SELECT browser_retry_until, browser_retry_pair FROM refresh_tokens WHERE token_hash = ? AND revoked_at IS NOT NULL AND expires_at > ?",
    ).bind(&token_hash).bind(now).fetch_optional(&mut *tx).await?;

    if let Some((Some(until), Some(encrypted))) = retry {
        if until > now {
            let mut pair = decrypt_browser_retry(&encrypted, signing_key)?;
            // Another tab may already have refreshed this replacement. Follow
            // the short retry chain so an older response cannot restore a
            // credential that has already been consumed.
            for _ in 0..16 {
                verify_access_token(&pair.access_token, signing_key, &mut tx).await?;
                let replacement = sqlx::query_as::<_, (Option<i64>, Option<i64>, Option<Vec<u8>>)>(
                    "SELECT revoked_at, browser_retry_until, browser_retry_pair FROM refresh_tokens WHERE token_hash = ? AND expires_at > ?",
                ).bind(hash_token(&pair.refresh_token)).bind(now).fetch_optional(&mut *tx).await?;
                match replacement {
                    Some((None, _, _)) => {
                        tx.commit().await?;
                        return Ok(pair);
                    }
                    Some((Some(_), Some(until), Some(encrypted))) if until > now => {
                        pair = decrypt_browser_retry(&encrypted, signing_key)?;
                    }
                    _ => return Err(AppError::AuthenticationRequired),
                }
            }
            return Err(AppError::AuthenticationRequired);
        }
    }

    let pair = match rotate_token_pair(token, signing_key, &mut tx).await {
        Ok(pair) => pair,
        Err(error @ AppError::AuthenticationRequired) => {
            // Preserve replay-triggered revocation even though refresh failed.
            tx.commit().await?;
            return Err(error);
        }
        Err(other) => return Err(other),
    };
    let encrypted = encrypt_browser_retry(&pair, signing_key)?;
    sqlx::query("UPDATE refresh_tokens SET browser_retry_until = ?, browser_retry_pair = ? WHERE token_hash = ?")
        .bind(now + 5).bind(encrypted).bind(token_hash).execute(&mut *tx).await?;
    // Discard encrypted credentials promptly after the concurrency window.
    sqlx::query("UPDATE refresh_tokens SET browser_retry_pair = NULL WHERE browser_retry_until <= ? AND browser_retry_pair IS NOT NULL")
        .bind(now).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(pair)
}

fn browser_retry_cipher(signing_key: &SigningKey) -> Aes256Gcm {
    // Separate the retry-encryption key from the Ed25519 signing key.
    let mut hash = Sha256::new();
    hash.update(b"authere/browser-refresh-retry/v1\0");
    hash.update(signing_key.as_bytes());
    Aes256Gcm::new(&hash.finalize())
}

fn encrypt_browser_retry(pair: &TokenPair, signing_key: &SigningKey) -> Result<Vec<u8>, AppError> {
    let plaintext = serde_json::to_vec(pair).map_err(|error| {
        AppError::InternalError(format!("Failed to encode refresh retry: {error}"))
    })?;
    let mut nonce = [0; 12];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = browser_retry_cipher(signing_key)
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_slice())
        .map_err(|_| AppError::InternalError("Failed to encrypt refresh retry".into()))?;
    Ok([nonce.as_slice(), ciphertext.as_slice()].concat())
}

fn decrypt_browser_retry(
    encrypted: &[u8],
    signing_key: &SigningKey,
) -> Result<TokenPair, AppError> {
    if encrypted.len() < 12 {
        return Err(AppError::AuthenticationRequired);
    }
    let plaintext = browser_retry_cipher(signing_key)
        .decrypt(Nonce::from_slice(&encrypted[..12]), &encrypted[12..])
        .map_err(|_| AppError::AuthenticationRequired)?;
    serde_json::from_slice(&plaintext).map_err(|_| AppError::AuthenticationRequired)
}

pub async fn sweep_expired_sessions(conn: &mut SqliteConnection) -> Result<(), AppError> {
    let now = current_timestamp();
    sqlx::query("UPDATE refresh_tokens SET browser_retry_pair = NULL WHERE browser_retry_until <= ? AND browser_retry_pair IS NOT NULL")
        .bind(now).execute(&mut *conn).await?;
    sqlx::query("DELETE FROM refresh_tokens WHERE expires_at <= ?")
        .bind(now)
        .execute(&mut *conn)
        .await?;
    sqlx::query("DELETE FROM forward_handoffs WHERE expires_at <= ?")
        .bind(now)
        .execute(conn)
        .await?;
    Ok(())
}

// ============================================================================
// Token Revocation
// ============================================================================

/// Revokes all access tokens for a user issued at or before now.
pub async fn revoke_user_access_tokens(
    user_id: Uuid,
    conn: &mut SqliteConnection,
) -> Result<(), AppError> {
    let now = current_timestamp();
    sqlx::query("UPDATE users SET token_version = token_version + 1 WHERE id = ?")
        .bind(user_id)
        .execute(&mut *conn)
        .await?;
    query!(
        "INSERT INTO user_access_revocations (user_id, revoked_before) VALUES (?, ?)
         ON CONFLICT(user_id) DO UPDATE SET revoked_before = excluded.revoked_before",
        user_id,
        now
    )
    .execute(conn)
    .await?;
    Ok(())
}

/// Revokes all refresh tokens and access tokens for a user (e.g. on password change)
pub async fn revoke_all_user_tokens(
    user_id: Uuid,
    conn: &mut SqliteConnection,
) -> Result<(), AppError> {
    let now = current_timestamp();

    query!(
        "UPDATE refresh_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
        now,
        user_id
    )
    .execute(&mut *conn)
    .await?;

    revoke_user_access_tokens(user_id, conn).await?;

    Ok(())
}

fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::User;
    use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};

    async fn in_memory_pool() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!("../migrations").run(&pool).await.unwrap();
        pool
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key_bytes: [u8; 32] = [42u8; 32];
        let kek: [u8; 32] = [99u8; 32];

        let (ciphertext, nonce) = encrypt_private_key(&key_bytes, &kek).unwrap();
        let decrypted = decrypt_private_key(&ciphertext, &nonce, &kek).unwrap();

        assert_eq!(key_bytes, decrypted);
    }

    #[test]
    fn decrypt_with_wrong_kek_fails() {
        let key_bytes: [u8; 32] = [42u8; 32];
        let kek: [u8; 32] = [99u8; 32];
        let wrong_kek: [u8; 32] = [1u8; 32];

        let (ciphertext, nonce) = encrypt_private_key(&key_bytes, &kek).unwrap();
        let result = decrypt_private_key(&ciphertext, &nonce, &wrong_kek);

        assert!(result.is_err());
    }

    #[test]
    fn encrypt_produces_different_ciphertexts() {
        let key_bytes: [u8; 32] = [42u8; 32];
        let kek: [u8; 32] = [99u8; 32];

        let (ct1, _) = encrypt_private_key(&key_bytes, &kek).unwrap();
        let (ct2, _) = encrypt_private_key(&key_bytes, &kek).unwrap();

        assert_ne!(
            ct1, ct2,
            "random nonces should produce different ciphertexts"
        );
    }

    #[test]
    fn hash_token_deterministic() {
        let h1 = hash_token("test-token");
        let h2 = hash_token("test-token");
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_token_different_inputs() {
        let h1 = hash_token("token-a");
        let h2 = hash_token("token-b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_token_is_hex_sha256() {
        let h = hash_token("hello");
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn claims_serialization_roundtrip() {
        let claims = Claims {
            sub: "user-123".into(),
            iss: TOKEN_ISSUER.into(),
            aud: TOKEN_AUDIENCE.into(),
            roles: vec!["admin".into(), "user".into()],
            exp: 1700000000,
            iat: 1699999000,
            jti: "jti-abc".into(),
            typ: "access".into(),
            session_exp: Some(1700000000),
            session_version: Some(0),
            auth_time: Some(1699999000),
        };

        let json = serde_json::to_string(&claims).unwrap();
        let deserialized: Claims = serde_json::from_str(&json).unwrap();

        assert_eq!(claims.sub, deserialized.sub);
        assert_eq!(claims.iss, deserialized.iss);
        assert_eq!(claims.aud, deserialized.aud);
        assert_eq!(claims.roles, deserialized.roles);
        assert_eq!(claims.exp, deserialized.exp);
        assert_eq!(claims.iat, deserialized.iat);
        assert_eq!(claims.jti, deserialized.jti);
        assert_eq!(claims.typ, deserialized.typ);
    }

    #[test]
    fn token_pair_serialization() {
        let pair = TokenPair {
            access_token: "at".into(),
            refresh_token: "rt".into(),
            expires_in: 900,
            refresh_expires_in: 604_800,
            token_type: "Bearer".into(),
        };
        let json = serde_json::to_string(&pair).unwrap();
        let deserialized: TokenPair = serde_json::from_str(&json).unwrap();
        assert_eq!(pair.access_token, deserialized.access_token);
        assert_eq!(pair.refresh_token, deserialized.refresh_token);
        assert_eq!(pair.expires_in, deserialized.expires_in);
        assert_eq!(pair.refresh_expires_in, deserialized.refresh_expires_in);
        assert_eq!(pair.token_type, deserialized.token_type);
    }

    #[test]
    fn constants_are_sensible() {
        assert_eq!(ACCESS_TOKEN_LIFETIME, 15 * 60);
        assert_eq!(REFRESH_TOKEN_LIFETIME, 7 * 24 * 60 * 60);
        assert!(ACCESS_TOKEN_LIFETIME < REFRESH_TOKEN_LIFETIME);
    }

    #[test]
    fn current_timestamp_is_reasonable() {
        let ts = current_timestamp();
        assert!(ts > 1_700_000_000, "timestamp should be after 2023");
        assert!(ts < 2_000_000_000, "timestamp should be before 2033");
    }

    #[test]
    fn generate_key_produces_valid_key() {
        let key = generate_key();
        let verifying = key.verifying_key();
        let message = b"test message";

        use ed25519_dalek::Signer;
        let signature = key.sign(message);

        use ed25519_dalek::Verifier;
        assert!(verifying.verify(message, &signature).is_ok());
    }

    #[test]
    fn generate_access_token_is_sync() {
        let key = generate_key();
        let result = generate_access_token(Uuid::new_v4(), vec!["user".into()], &key);
        assert!(result.is_ok());
        let token = result.unwrap();
        assert!(!token.is_empty());
    }

    #[test]
    fn generate_access_token_different_each_time() {
        let key = generate_key();
        let uid = Uuid::new_v4();
        let t1 = generate_access_token(uid, vec![], &key).unwrap();
        let t2 = generate_access_token(uid, vec![], &key).unwrap();
        assert_ne!(t1, t2, "each token should have a unique jti");
    }

    #[tokio::test]
    async fn verify_access_token_accepts_active_user() {
        let pool = in_memory_pool().await;
        let mut conn = pool.acquire().await.unwrap();

        let user = User::new("a".into(), "Alice".into(), None);
        user.save(&mut conn).await.unwrap();

        let key = generate_key();
        let token = generate_access_token(user.id, vec!["user".into()], &key).unwrap();

        let claims = verify_access_token(&token, &key, &mut conn).await.unwrap();
        assert_eq!(claims.sub, user.id.to_string());
    }

    #[tokio::test]
    async fn verify_access_token_rejects_inactive_user() {
        let pool = in_memory_pool().await;
        let mut conn = pool.acquire().await.unwrap();

        let mut user = User::new("a".into(), "Alice".into(), None);
        user.save(&mut conn).await.unwrap();

        let key = generate_key();
        let token = generate_access_token(user.id, vec!["user".into()], &key).unwrap();

        user.set_active(false, &mut conn).await.unwrap();

        let err = verify_access_token(&token, &key, &mut conn)
            .await
            .expect_err("inactive users must not be able to present access tokens");
        assert!(matches!(err, AppError::AuthenticationRequired));
    }

    #[tokio::test]
    async fn token_pair_reflects_configured_session_expiry() {
        use crate::settings::{KEY_SESSION_EXPIRY_SECONDS, set_setting};

        let pool = in_memory_pool().await;
        let mut conn = pool.acquire().await.unwrap();

        let user = User::new("expiry-user".into(), "Expiry".into(), None);
        user.save(&mut conn).await.unwrap();

        set_setting(KEY_SESSION_EXPIRY_SECONDS, "3600", &mut conn)
            .await
            .unwrap();

        let key = generate_key();
        let pair = generate_token_pair(user.id, vec![], &key, &mut conn)
            .await
            .unwrap();

        assert_eq!(
            pair.refresh_expires_in, 3600,
            "refresh_expires_in should mirror the configured setting"
        );
        assert_eq!(
            pair.expires_in, ACCESS_TOKEN_LIFETIME,
            "access token lifetime remains a compile-time constant"
        );
    }

    #[tokio::test]
    async fn refresh_token_expiry_honors_lifetime_arg() {
        let pool = in_memory_pool().await;
        let mut conn = pool.acquire().await.unwrap();

        let user = User::new("rt-user".into(), "Refresh".into(), None);
        user.save(&mut conn).await.unwrap();

        let key = generate_key();
        let _ = generate_refresh_token(user.id, 600, &key, &mut conn)
            .await
            .unwrap();

        let row = query!(
            r#"SELECT expires_at, created_at FROM refresh_tokens WHERE user_id = ?"#,
            user.id
        )
        .fetch_one(&mut *conn)
        .await
        .unwrap();

        assert_eq!(row.expires_at - row.created_at, 600);
    }

    #[tokio::test]
    async fn short_session_caps_access_and_refresh_at_the_same_deadline() {
        let pool = in_memory_pool().await;
        let mut conn = pool.acquire().await.unwrap();
        let user = User::new("short-session".into(), "Short".into(), None);
        user.save(&mut conn).await.unwrap();
        crate::settings::set_setting(
            crate::settings::KEY_SESSION_EXPIRY_SECONDS,
            "300",
            &mut conn,
        )
        .await
        .unwrap();
        let key = generate_key();
        let pair = generate_token_pair(user.id, vec![], &key, &mut conn)
            .await
            .unwrap();
        let claims = verify_access_token(&pair.access_token, &key, &mut conn)
            .await
            .unwrap();
        assert!(pair.expires_in <= 300);
        assert_eq!(pair.expires_in, pair.refresh_expires_in);
        assert_eq!(Some(claims.exp), claims.session_exp);
        let (_, refresh) = consume_refresh_token(&pair.refresh_token, &key, &mut conn)
            .await
            .unwrap();
        assert_eq!(claims.exp, refresh.exp);
    }

    #[tokio::test]
    async fn refresh_preserves_deadline_even_when_setting_increases() {
        let pool = in_memory_pool().await;
        let mut conn = pool.acquire().await.unwrap();
        let user = User::new("absolute-session".into(), "Absolute".into(), None);
        user.save(&mut conn).await.unwrap();
        let key = generate_key();
        let deadline = current_timestamp() + 120;
        let auth_time = current_timestamp() - 100;
        let pair = generate_token_pair_for_session(
            user.id,
            vec![],
            deadline,
            Some(0),
            auth_time,
            &key,
            &mut conn,
        )
        .await
        .unwrap();
        crate::settings::set_setting(
            crate::settings::KEY_SESSION_EXPIRY_SECONDS,
            "31536000",
            &mut conn,
        )
        .await
        .unwrap();
        let rotated = rotate_token_pair(&pair.refresh_token, &key, &mut conn)
            .await
            .unwrap();
        let claims = verify_access_token(&rotated.access_token, &key, &mut conn)
            .await
            .unwrap();
        assert_eq!(claims.exp, deadline);
        assert_eq!(claims.session_exp, Some(deadline));
        assert_eq!(claims.auth_time, Some(auth_time));
        let (_, refresh) = consume_refresh_token(&rotated.refresh_token, &key, &mut conn)
            .await
            .unwrap();
        assert_eq!(refresh.exp, deadline);
    }

    #[tokio::test]
    async fn concurrent_browser_refreshes_return_one_replacement_and_late_replay_revokes_it() {
        let pool = in_memory_pool().await;
        let mut conn = pool.acquire().await.unwrap();
        let user = User::new("browser-retries".into(), "Browser".into(), None);
        user.save(&mut conn).await.unwrap();
        let key = generate_key();
        let pair = generate_token_pair(user.id, vec![], &key, &mut conn)
            .await
            .unwrap();
        drop(conn);

        let mut first_conn = pool.acquire().await.unwrap();
        let mut second_conn = pool.acquire().await.unwrap();
        let (first, second) = tokio::join!(
            rotate_browser_token_pair(&pair.refresh_token, &key, &mut first_conn),
            rotate_browser_token_pair(&pair.refresh_token, &key, &mut second_conn),
        );
        let first = first.unwrap();
        let second = second.unwrap();
        assert_eq!(first.access_token, second.access_token);
        assert_eq!(first.refresh_token, second.refresh_token);
        verify_access_token(&first.access_token, &key, &mut first_conn)
            .await
            .unwrap();
        let encrypted: Vec<u8> = sqlx::query_scalar(
            "SELECT browser_retry_pair FROM refresh_tokens WHERE token_hash = ?",
        )
        .bind(hash_token(&pair.refresh_token))
        .fetch_one(&mut *first_conn)
        .await
        .unwrap();
        assert!(
            !encrypted
                .windows(first.refresh_token.len())
                .any(|slice| slice == first.refresh_token.as_bytes())
        );
        let cutoff = current_timestamp() - 1;
        sqlx::query("UPDATE refresh_tokens SET browser_retry_until = ? WHERE token_hash = ?")
            .bind(cutoff)
            .bind(hash_token(&pair.refresh_token))
            .execute(&mut *first_conn)
            .await
            .unwrap();
        assert!(
            rotate_browser_token_pair(&pair.refresh_token, &key, &mut first_conn)
                .await
                .is_err()
        );
        assert!(
            verify_access_token(&first.access_token, &key, &mut first_conn)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn browser_retry_cannot_survive_logout_or_extend_the_session() {
        let pool = in_memory_pool().await;
        let mut conn = pool.acquire().await.unwrap();
        let user = User::new("retry-logout".into(), "Retry".into(), None);
        user.save(&mut conn).await.unwrap();
        let key = generate_key();
        let deadline = current_timestamp() + 120;
        let pair = generate_token_pair_for_session(
            user.id,
            vec![],
            deadline,
            Some(0),
            current_timestamp(),
            &key,
            &mut conn,
        )
        .await
        .unwrap();
        let rotated = rotate_browser_token_pair(&pair.refresh_token, &key, &mut conn)
            .await
            .unwrap();
        assert_eq!(
            verify_access_token(&rotated.access_token, &key, &mut conn)
                .await
                .unwrap()
                .exp,
            deadline
        );
        revoke_user_access_tokens(user.id, &mut conn).await.unwrap();
        assert!(
            rotate_browser_token_pair(&pair.refresh_token, &key, &mut conn)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn delayed_browser_retry_returns_the_latest_active_refresh_credential() {
        let pool = in_memory_pool().await;
        let mut conn = pool.acquire().await.unwrap();
        let user = User::new("retry-chain".into(), "Chain".into(), None);
        user.save(&mut conn).await.unwrap();
        let key = generate_key();
        let original = generate_token_pair(user.id, vec![], &key, &mut conn)
            .await
            .unwrap();
        let first = rotate_browser_token_pair(&original.refresh_token, &key, &mut conn)
            .await
            .unwrap();
        let latest = rotate_browser_token_pair(&first.refresh_token, &key, &mut conn)
            .await
            .unwrap();
        assert_ne!(first.refresh_token, latest.refresh_token);
        let delayed = rotate_browser_token_pair(&original.refresh_token, &key, &mut conn)
            .await
            .unwrap();
        assert_eq!(delayed.refresh_token, latest.refresh_token);
        assert_eq!(delayed.access_token, latest.access_token);
        rotate_browser_token_pair(&delayed.refresh_token, &key, &mut conn)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn logout_revokes_refresh_and_access_but_allows_immediate_new_login() {
        let pool = in_memory_pool().await;
        let mut conn = pool.acquire().await.unwrap();
        let user = User::new("relogin".into(), "Relogin".into(), None);
        user.save(&mut conn).await.unwrap();
        let key = generate_key();
        let old = generate_token_pair(user.id, vec![], &key, &mut conn)
            .await
            .unwrap();
        revoke_user_access_tokens(user.id, &mut conn).await.unwrap();
        assert!(
            verify_access_token(&old.access_token, &key, &mut conn)
                .await
                .is_err()
        );
        assert!(
            rotate_token_pair(&old.refresh_token, &key, &mut conn)
                .await
                .is_err()
        );
        let fresh = generate_token_pair(user.id, vec![], &key, &mut conn)
            .await
            .unwrap();
        verify_access_token(&fresh.access_token, &key, &mut conn)
            .await
            .unwrap();
        rotate_token_pair(&fresh.refresh_token, &key, &mut conn)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn inactive_users_cannot_refresh_and_replay_revokes_rotated_credentials() {
        let pool = in_memory_pool().await;
        let mut conn = pool.acquire().await.unwrap();
        let mut user = User::new("inactive-refresh".into(), "Inactive".into(), None);
        user.save(&mut conn).await.unwrap();
        let key = generate_key();
        let old = generate_token_pair(user.id, vec![], &key, &mut conn)
            .await
            .unwrap();
        user.set_active(false, &mut conn).await.unwrap();
        assert!(
            rotate_token_pair(&old.refresh_token, &key, &mut conn)
                .await
                .is_err()
        );
        user.set_active(true, &mut conn).await.unwrap();
        let fresh = rotate_token_pair(&old.refresh_token, &key, &mut conn)
            .await
            .unwrap();
        assert!(
            rotate_token_pair(&old.refresh_token, &key, &mut conn)
                .await
                .is_err()
        );
        assert!(
            verify_access_token(&fresh.access_token, &key, &mut conn)
                .await
                .is_err()
        );
        assert!(
            rotate_token_pair(&fresh.refresh_token, &key, &mut conn)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn access_verification_reads_current_roles_and_rejects_exact_expiry() {
        let pool = in_memory_pool().await;
        let mut conn = pool.acquire().await.unwrap();
        let user = User::new("current-roles".into(), "Roles".into(), None);
        user.save(&mut conn).await.unwrap();
        let key = generate_key();
        let stale = generate_access_token(user.id, vec!["admin".into()], &key).unwrap();
        let verified = verify_access_token(&stale, &key, &mut conn).await.unwrap();
        assert!(
            verified.roles.is_empty(),
            "signed roles do not override current permissions"
        );
        let expired = generate_access_token_for_session(
            user.id,
            vec![],
            current_timestamp(),
            Some(0),
            current_timestamp(),
            &key,
        )
        .unwrap();
        assert!(
            verify_access_token(&expired, &key, &mut conn)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn verify_access_token_rejects_unknown_user() {
        // If the user has been hard-deleted, an otherwise-valid token should no longer work.
        let pool = in_memory_pool().await;
        let mut conn = pool.acquire().await.unwrap();
        let key = generate_key();
        let ghost_id = Uuid::now_v7();
        let token = generate_access_token(ghost_id, vec![], &key).unwrap();

        let err = verify_access_token(&token, &key, &mut conn)
            .await
            .expect_err("tokens for non-existent users must be rejected");
        assert!(matches!(err, AppError::AuthenticationRequired));
    }
}

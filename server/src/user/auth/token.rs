use crate::errors::AppError;

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use ed25519_dalek::{SigningKey, pkcs8::EncodePrivateKey};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, SqliteConnection, query};
use utoipa::ToSchema;
use uuid::Uuid;

/// Access token lifetime in seconds (15 minutes)
pub const ACCESS_TOKEN_LIFETIME: i64 = 15 * 60;
/// Refresh token lifetime in seconds (7 days)
pub const REFRESH_TOKEN_LIFETIME: i64 = 7 * 24 * 60 * 60;

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
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
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
            AppError::InternalError(
                "Key decryption failed — check AUTHERE_KEY_SECRET".to_string(),
            )
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
    let now = current_timestamp();

    let claims = Claims {
        sub: user_id.to_string(),
        iss: TOKEN_ISSUER.to_string(),
        aud: TOKEN_AUDIENCE.to_string(),
        roles,
        exp: now + ACCESS_TOKEN_LIFETIME,
        iat: now,
        jti: Uuid::new_v4().to_string(),
        typ: "access".to_string(),
    };

    let header = Header::new(Algorithm::EdDSA);
    let pkcs8_der = signing_key.to_pkcs8_der()
        .map_err(|e| AppError::InternalError(format!("Failed to encode signing key: {e}")))?;
    let encoding_key = EncodingKey::from_ed_der(pkcs8_der.as_bytes());

    encode(&header, &claims, &encoding_key)
        .map_err(|e| AppError::InternalError(format!("Failed to encode JWT: {e}")))
}

/// Generates a refresh token and stores it in the database
pub async fn generate_refresh_token(
    user_id: Uuid,
    signing_key: &SigningKey,
    conn: &mut SqliteConnection,
) -> Result<String, AppError> {
    let now = current_timestamp();

    let claims = Claims {
        sub: user_id.to_string(),
        iss: TOKEN_ISSUER.to_string(),
        aud: TOKEN_AUDIENCE.to_string(),
        roles: vec![], // Refresh tokens don't carry roles
        exp: now + REFRESH_TOKEN_LIFETIME,
        iat: now,
        jti: Uuid::new_v4().to_string(),
        typ: "refresh".to_string(),
    };

    let header = Header::new(Algorithm::EdDSA);
    let pkcs8_der = signing_key.to_pkcs8_der()
        .map_err(|e| AppError::InternalError(format!("Failed to encode signing key: {e}")))?;
    let encoding_key = EncodingKey::from_ed_der(pkcs8_der.as_bytes());

    let token = encode(&header, &claims, &encoding_key)
        .map_err(|e| AppError::InternalError(format!("Failed to encode JWT: {e}")))?;

    let token_hash = hash_token(&token);
    let id = Uuid::now_v7();
    let expires_at = now + REFRESH_TOKEN_LIFETIME;

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

/// Generates both access and refresh tokens for a user
pub async fn generate_token_pair(
    user_id: Uuid,
    roles: Vec<String>,
    signing_key: &SigningKey,
    conn: &mut SqliteConnection,
) -> Result<TokenPair, AppError> {
    let access_token = generate_access_token(user_id, roles, signing_key)?;
    let refresh_token = generate_refresh_token(user_id, signing_key, conn).await?;

    Ok(TokenPair {
        access_token,
        refresh_token,
        expires_in: ACCESS_TOKEN_LIFETIME,
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
    validation.set_required_spec_claims(&["sub", "exp", "iat", "jti", "typ", "iss", "aud"]);
    validation.set_issuer(&[TOKEN_ISSUER]);
    validation.set_audience(&[TOKEN_AUDIENCE]);

    let token_data = decode::<Claims>(token, &decoding_key, &validation)
        .map_err(|_| AppError::AuthenticationRequired)?;

    if token_data.claims.typ != "access" {
        return Err(AppError::AuthenticationRequired);
    }

    let user_id = Uuid::parse_str(&token_data.claims.sub)
        .map_err(|_| AppError::InternalError("Invalid user ID in token".to_string()))?;

    let revocation = query!(
        "SELECT revoked_before FROM user_access_revocations WHERE user_id = ?",
        user_id
    )
    .fetch_optional(conn)
    .await?;

    if let Some(r) = revocation {
        if token_data.claims.iat <= r.revoked_before {
            return Err(AppError::AuthenticationRequired);
        }
    }

    Ok(token_data.claims)
}

/// Atomically verifies a refresh token and revokes it in a single DB operation.
pub async fn verify_and_revoke_refresh_token(
    token: &str,
    signing_key: &SigningKey,
    conn: &mut SqliteConnection,
) -> Result<Uuid, AppError> {
    let verifying_key = signing_key.verifying_key();
    let decoding_key = DecodingKey::from_ed_der(&verifying_key.to_bytes());

    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_required_spec_claims(&["sub", "exp", "iat", "jti", "typ", "iss", "aud"]);
    validation.set_issuer(&[TOKEN_ISSUER]);
    validation.set_audience(&[TOKEN_AUDIENCE]);

    let token_data = decode::<Claims>(token, &decoding_key, &validation)
        .map_err(|_| AppError::AuthenticationRequired)?;

    if token_data.claims.typ != "refresh" {
        return Err(AppError::AuthenticationRequired);
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

    let user_id = Uuid::parse_str(&token_data.claims.sub)
        .map_err(|_| AppError::InternalError("Invalid user ID in token".to_string()))?;
    Ok(user_id)
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

        assert_ne!(ct1, ct2, "random nonces should produce different ciphertexts");
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
            token_type: "Bearer".into(),
        };
        let json = serde_json::to_string(&pair).unwrap();
        let deserialized: TokenPair = serde_json::from_str(&json).unwrap();
        assert_eq!(pair.access_token, deserialized.access_token);
        assert_eq!(pair.refresh_token, deserialized.refresh_token);
        assert_eq!(pair.expires_in, deserialized.expires_in);
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
}

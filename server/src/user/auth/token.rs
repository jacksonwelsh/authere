use crate::errors::AppError;

use ed25519_dalek::{SigningKey, VerifyingKey};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, SqliteConnection, query};
use utoipa::ToSchema;
use uuid::Uuid;

/// Access token lifetime in seconds (15 minutes)
pub const ACCESS_TOKEN_LIFETIME: i64 = 15 * 60;
/// Refresh token lifetime in seconds (7 days)
pub const REFRESH_TOKEN_LIFETIME: i64 = 7 * 24 * 60 * 60;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (user ID)
    pub sub: String,
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

fn generate_key() -> SigningKey {
    let mut rng = OsRng;
    SigningKey::generate(&mut rng)
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

    let id = Uuid::now_v7();
    let public_key = key.verifying_key().to_bytes();
    let private_key = key.to_bytes();

    let pubk_slice = &public_key[..];
    let privk_slice = &private_key[..];

    query!(
        "INSERT INTO keys (id, name, public_key, private_key) VALUES (?, 'default', ?, ?)",
        id,
        pubk_slice,
        privk_slice,
    )
    .execute(conn)
    .await?;

    Ok(())
}

async fn get_signing_key(conn: &mut SqliteConnection) -> Result<SigningKey, AppError> {
    let row = query!("SELECT private_key FROM keys WHERE name = 'default'")
        .fetch_one(conn)
        .await?;

    let private_key: [u8; 32] = row
        .private_key
        .try_into()
        .map_err(|_| AppError::InternalError("Invalid key length".to_string()))?;

    Ok(SigningKey::from_bytes(&private_key))
}

pub async fn get_verifying_key(conn: &mut SqliteConnection) -> Result<VerifyingKey, AppError> {
    let row = query!("SELECT public_key FROM keys WHERE name = 'default'")
        .fetch_one(conn)
        .await?;

    let public_key: [u8; 32] = row
        .public_key
        .try_into()
        .map_err(|_| AppError::InternalError("Invalid key length".to_string()))?;

    VerifyingKey::from_bytes(&public_key)
        .map_err(|e| AppError::InternalError(format!("Invalid public key: {e}")))
}

fn current_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as i64
}

/// Generates an access token for the given user
pub async fn generate_access_token(
    user_id: Uuid,
    roles: Vec<String>,
    conn: &mut SqliteConnection,
) -> Result<String, AppError> {
    let signing_key = get_signing_key(conn).await?;
    let now = current_timestamp();

    let claims = Claims {
        sub: user_id.to_string(),
        roles,
        exp: now + ACCESS_TOKEN_LIFETIME,
        iat: now,
        jti: Uuid::now_v7().to_string(),
        typ: "access".to_string(),
    };

    let header = Header::new(Algorithm::EdDSA);
    let encoding_key = EncodingKey::from_ed_der(&signing_key.to_keypair_bytes());

    encode(&header, &claims, &encoding_key)
        .map_err(|e| AppError::InternalError(format!("Failed to encode JWT: {e}")))
}

/// Generates a refresh token and stores it in the database
pub async fn generate_refresh_token(
    user_id: Uuid,
    conn: &mut SqliteConnection,
) -> Result<String, AppError> {
    let signing_key = get_signing_key(conn).await?;
    let now = current_timestamp();
    let token_id = Uuid::now_v7();

    let claims = Claims {
        sub: user_id.to_string(),
        roles: vec![], // Refresh tokens don't carry roles
        exp: now + REFRESH_TOKEN_LIFETIME,
        iat: now,
        jti: token_id.to_string(),
        typ: "refresh".to_string(),
    };

    let header = Header::new(Algorithm::EdDSA);
    let encoding_key = EncodingKey::from_ed_der(&signing_key.to_keypair_bytes());

    let token = encode(&header, &claims, &encoding_key)
        .map_err(|e| AppError::InternalError(format!("Failed to encode JWT: {e}")))?;

    // Hash the token for storage
    let token_hash = hash_token(&token);

    // Store in database
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
    conn: &mut SqliteConnection,
) -> Result<TokenPair, AppError> {
    let access_token = generate_access_token(user_id, roles, &mut *conn).await?;
    let refresh_token = generate_refresh_token(user_id, conn).await?;

    Ok(TokenPair {
        access_token,
        refresh_token,
        expires_in: ACCESS_TOKEN_LIFETIME,
        token_type: "Bearer".to_string(),
    })
}

/// Verifies an access token and returns the claims
pub async fn verify_access_token(
    token: &str,
    conn: &mut SqliteConnection,
) -> Result<Claims, AppError> {
    let verifying_key = get_verifying_key(conn).await?;
    let decoding_key = DecodingKey::from_ed_der(&verifying_key.to_bytes());

    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_required_spec_claims(&["sub", "exp", "iat", "jti", "typ"]);

    let token_data = decode::<Claims>(token, &decoding_key, &validation)
        .map_err(|_| AppError::AuthenticationRequired)?;

    // Verify it's an access token
    if token_data.claims.typ != "access" {
        return Err(AppError::AuthenticationRequired);
    }

    Ok(token_data.claims)
}

/// Verifies a refresh token and returns the user ID if valid
pub async fn verify_refresh_token(
    token: &str,
    conn: &mut SqliteConnection,
) -> Result<Uuid, AppError> {
    let verifying_key = get_verifying_key(conn).await?;
    let decoding_key = DecodingKey::from_ed_der(&verifying_key.to_bytes());

    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_required_spec_claims(&["sub", "exp", "iat", "jti", "typ"]);

    let token_data = decode::<Claims>(token, &decoding_key, &validation)
        .map_err(|_| AppError::AuthenticationRequired)?;

    // Verify it's a refresh token
    if token_data.claims.typ != "refresh" {
        return Err(AppError::AuthenticationRequired);
    }

    // Check if token is in the database and not revoked
    let token_hash = hash_token(token);
    let now = current_timestamp();

    let record = query!(
        "SELECT id, revoked_at FROM refresh_tokens WHERE token_hash = ? AND expires_at > ?",
        token_hash,
        now
    )
    .fetch_optional(&mut *conn)
    .await?;

    match record {
        Some(r) if r.revoked_at.is_none() => {
            let user_id = Uuid::parse_str(&token_data.claims.sub)
                .map_err(|_| AppError::InternalError("Invalid user ID in token".to_string()))?;
            Ok(user_id)
        }
        _ => Err(AppError::AuthenticationRequired),
    }
}

/// Revokes a refresh token
pub async fn revoke_refresh_token(token: &str, conn: &mut SqliteConnection) -> Result<(), AppError> {
    let token_hash = hash_token(token);
    let now = current_timestamp();

    query!(
        "UPDATE refresh_tokens SET revoked_at = ? WHERE token_hash = ?",
        now,
        token_hash
    )
    .execute(conn)
    .await?;

    Ok(())
}

/// Revokes all refresh tokens for a user
pub async fn revoke_all_user_tokens(user_id: Uuid, conn: &mut SqliteConnection) -> Result<(), AppError> {
    let now = current_timestamp();

    query!(
        "UPDATE refresh_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
        now,
        user_id
    )
    .execute(conn)
    .await?;

    Ok(())
}

fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

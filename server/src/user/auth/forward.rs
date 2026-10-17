//! Credentials used only by the reverse-proxy login flow. A protected upstream
//! must never receive credentials that authorize requests to Authere's own API.
use ed25519_dalek::{SigningKey, pkcs8::EncodePrivateKey};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::SqliteConnection;
use uuid::Uuid;

use super::token::{Claims, verify_user_session};
use crate::errors::AppError;

pub const SESSION_COOKIE: &str = "__Host-authere_forward";
pub const STATE_COOKIE: &str = "__Host-authere_forward_state";
const ISSUER: &str = "authere-forward";

#[derive(Debug, Serialize, Deserialize)]
pub struct ForwardSession {
    pub sub: Uuid,
    pub application_id: Uuid,
    pub iss: String,
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
    pub session_version: Option<i64>,
    pub typ: String,
}

#[derive(Serialize, Deserialize)]
struct Handoff {
    session: ForwardSession,
    state_hash: String,
    redirect_path: String,
    jti: String,
    iss: String,
    aud: String,
    exp: i64,
    typ: String,
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as i64
}

pub fn new_state() -> String {
    let mut bytes = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

pub fn valid_state(state: &str) -> bool {
    state.len() == 64 && state.bytes().all(|b| b.is_ascii_hexdigit())
}

fn state_hash(state: &str) -> String {
    hex::encode(Sha256::digest(state.as_bytes()))
}

fn sign<T: Serialize>(claims: &T, key: &SigningKey) -> Result<String, AppError> {
    let der = key
        .to_pkcs8_der()
        .map_err(|e| AppError::InternalError(format!("Failed to encode signing key: {e}")))?;
    encode(
        &Header::new(Algorithm::EdDSA),
        claims,
        &EncodingKey::from_ed_der(der.as_bytes()),
    )
    .map_err(|e| AppError::InternalError(format!("Failed to sign forward credential: {e}")))
}

fn validation(origin: &str) -> Validation {
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_issuer(&[ISSUER]);
    validation.set_audience(&[origin]);
    validation.set_required_spec_claims(&["iss", "aud", "exp"]);
    validation.leeway = 0;
    validation
}

/// Create a short-lived, single-use transfer bound to the browser that started
/// the login and to the original session's absolute expiry and revocation version.
pub async fn issue_handoff(
    parent: &Claims,
    application_id: Uuid,
    target_origin: &str,
    redirect_path: &str,
    state: &str,
    key: &SigningKey,
    conn: &mut SqliteConnection,
) -> Result<String, AppError> {
    if !valid_state(state) {
        return Err(AppError::InputError(vec![
            "Invalid forward login state".into(),
        ]));
    }
    let user_id = Uuid::parse_str(&parent.sub).map_err(|_| AppError::AuthenticationRequired)?;
    let deadline = parent.session_exp.unwrap_or(parent.exp);
    if deadline <= now() {
        return Err(AppError::AuthenticationRequired);
    }
    verify_user_session(user_id, parent.iat, parent.session_version, conn).await?;
    let handoff = Handoff {
        session: ForwardSession {
            sub: user_id,
            application_id,
            iss: ISSUER.into(),
            aud: target_origin.into(),
            iat: parent.iat,
            exp: deadline,
            session_version: parent.session_version,
            typ: "forward-session".into(),
        },
        state_hash: state_hash(state),
        redirect_path: redirect_path.into(),
        jti: Uuid::new_v4().to_string(),
        iss: ISSUER.into(),
        aud: target_origin.into(),
        exp: deadline.min(now() + 60),
        typ: "forward-handoff".into(),
    };
    let token = sign(&handoff, key)?;
    sqlx::query("DELETE FROM forward_handoffs WHERE expires_at <= ?")
        .bind(now())
        .execute(&mut *conn)
        .await?;
    sqlx::query("INSERT INTO forward_handoffs (id, user_id, expires_at) VALUES (?, ?, ?)")
        .bind(&handoff.jti)
        .bind(user_id)
        .bind(handoff.exp)
        .execute(conn)
        .await?;
    Ok(token)
}

pub async fn redeem_handoff(
    token: &str,
    target_origin: &str,
    state: &str,
    key: &SigningKey,
    conn: &mut SqliteConnection,
) -> Result<(String, ForwardSession, String), AppError> {
    let decoded = decode::<Handoff>(
        token,
        &DecodingKey::from_ed_der(&key.verifying_key().to_bytes()),
        &validation(target_origin),
    )
    .map_err(|_| AppError::AuthenticationRequired)?
    .claims;
    if decoded.typ != "forward-handoff"
        || !valid_state(state)
        || decoded.state_hash != state_hash(state)
        || decoded.session.aud != target_origin
        || decoded.session.exp <= now()
    {
        return Err(AppError::AuthenticationRequired);
    }
    verify_user_session(
        decoded.session.sub,
        decoded.session.iat,
        decoded.session.session_version,
        conn,
    )
    .await?;
    let consumed =
        sqlx::query("DELETE FROM forward_handoffs WHERE id = ? AND user_id = ? AND expires_at > ?")
            .bind(&decoded.jti)
            .bind(decoded.session.sub)
            .bind(now())
            .execute(conn)
            .await?;
    if consumed.rows_affected() != 1 {
        return Err(AppError::AuthenticationRequired);
    }
    let session_token = sign(&decoded.session, key)?;
    Ok((session_token, decoded.session, decoded.redirect_path))
}

pub async fn verify_session(
    token: &str,
    target_origin: &str,
    key: &SigningKey,
    conn: &mut SqliteConnection,
) -> Result<ForwardSession, AppError> {
    let claims = decode::<ForwardSession>(
        token,
        &DecodingKey::from_ed_der(&key.verifying_key().to_bytes()),
        &validation(target_origin),
    )
    .map_err(|_| AppError::AuthenticationRequired)?
    .claims;
    if claims.typ != "forward-session" || claims.exp <= now() {
        return Err(AppError::AuthenticationRequired);
    }
    verify_user_session(claims.sub, claims.iat, claims.session_version, conn).await?;
    Ok(claims)
}

pub fn session_cookie(token: &str, lifetime: i64) -> String {
    format!("{SESSION_COOKIE}={token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={lifetime}")
}

pub fn state_cookie(state: &str, lifetime: i64) -> String {
    format!("{STATE_COOKIE}={state}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={lifetime}")
}

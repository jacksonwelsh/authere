//! User-verified WebAuthn credentials are complete MFA authenticators. Only this
//! cryptographically verified path may issue a session without password/TOTP.
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use rand::RngCore;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sqlx::{Connection, FromRow, SqliteConnection};
use utoipa::ToSchema;
use uuid::Uuid;
use webauthn_rs::prelude::*;

use crate::{
    AppState,
    audit::{AuditContext, AuditEventType, audit},
    auth_middleware::AuthUser,
    db::DbEntity,
    errors::AppError,
    handlers::{
        LoginError,
        auth::{BrowserLoginQuery, browser_login_response},
    },
    rate_limit::RateLimitExceeded,
    user::{
        User,
        auth::{token, totp::now_epoch},
    },
};

const CHALLENGE_TTL: i64 = 300;
const MAX_PASSKEYS: i64 = 20;

pub fn webauthn(origin: &str) -> Result<Webauthn, AppError> {
    let invalid = || {
        AppError::InputError(vec![
        "Passkeys require Authere's public HTTPS address (or http://localhost for development).".into(),
    ])
    };
    let url = Url::parse(origin).map_err(|_| invalid())?;
    let domain = url.domain().ok_or_else(invalid)?;
    if !(url.scheme() == "https" || (url.scheme() == "http" && domain == "localhost"))
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(invalid());
    }
    WebauthnBuilder::new(domain, &url)
        .map_err(|_| invalid())?
        .rp_name("Authere")
        .timeout(std::time::Duration::from_secs(CHALLENGE_TTL as u64))
        .build()
        .map_err(|e| AppError::InternalError(e.to_string()))
}

fn encode<T: Serialize>(value: &T) -> Result<String, AppError> {
    serde_json::to_string(value).map_err(|e| AppError::InternalError(e.to_string()))
}

fn decode<T: DeserializeOwned>(value: &str) -> Result<T, AppError> {
    serde_json::from_str(value).map_err(|e| AppError::InternalError(e.to_string()))
}

fn cookie_name(kind: &str) -> String {
    format!("__Host-authere_passkey_{kind}")
}

fn cookie_id<'a>(headers: &'a HeaderMap, kind: &str) -> Option<&'a str> {
    let name = cookie_name(kind);
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|part| {
            let (key, value) = part.trim().split_once('=')?;
            (key == name && value.len() == 64 && value.bytes().all(|c| c.is_ascii_hexdigit()))
                .then_some(value)
        })
}

fn challenge_cookie(kind: &str, id: &str, max_age: i64) -> String {
    format!(
        "{}={id}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={max_age}",
        cookie_name(kind)
    )
}

#[derive(FromRow)]
struct Challenge {
    user_id: Option<Uuid>,
    token_version: Option<i64>,
    name: Option<String>,
    state: String,
}

async fn save_challenge(
    conn: &mut SqliteConnection,
    headers: &HeaderMap,
    kind: &str,
    challenge: Challenge,
    options: Value,
) -> Result<Response, AppError> {
    sqlx::query("DELETE FROM passkey_challenges WHERE expires_at <= ? OR (id = ? AND kind = ?)")
        .bind(now_epoch())
        .bind(cookie_id(headers, kind))
        .bind(kind)
        .execute(&mut *conn)
        .await?;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let id = hex::encode(bytes);
    sqlx::query("INSERT INTO passkey_challenges (id, kind, user_id, token_version, name, state, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
        .bind(&id).bind(kind).bind(challenge.user_id).bind(challenge.token_version)
        .bind(challenge.name).bind(challenge.state).bind(now_epoch() + CHALLENGE_TTL)
        .execute(conn).await?;
    Ok((
        [(
            header::SET_COOKIE,
            challenge_cookie(kind, &id, CHALLENGE_TTL),
        )],
        Json(options),
    )
        .into_response())
}

/// DELETE RETURNING atomically consumes state before verification, including on
/// failure. Never wrap this in a transaction that can roll back and enable replay.
async fn take_challenge(
    conn: &mut SqliteConnection,
    headers: &HeaderMap,
    kind: &str,
) -> Result<Challenge, AppError> {
    let id = cookie_id(headers, kind).ok_or(AppError::AuthenticationRequired)?;
    sqlx::query_as::<_, Challenge>("DELETE FROM passkey_challenges WHERE id = ? AND kind = ? AND expires_at > ? RETURNING user_id, token_version, name, state")
        .bind(id).bind(kind).bind(now_epoch()).fetch_optional(conn).await?
        .ok_or(AppError::AuthenticationRequired)
}

async fn rate_limit(state: &AppState, ctx: &AuditContext) -> Result<(), LoginError> {
    state
        .login_rate_limiter
        .check(ctx.ip)
        .await
        .map(|_| ())
        .map_err(|retry_after| LoginError::RateLimit(RateLimitExceeded { retry_after }))
}

#[derive(Serialize, FromRow, ToSchema)]
pub struct PasskeyInfo {
    id: Uuid,
    name: String,
    created_at: i64,
    last_used_at: Option<i64>,
}

#[derive(Deserialize, ToSchema)]
pub struct RegisterInput {
    name: String,
}

#[utoipa::path(get, path = "/api/me/passkeys", responses((status = 200, body = Vec<PasskeyInfo>)), tag = "passkeys")]
pub async fn list(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<PasskeyInfo>>, AppError> {
    Ok(Json(sqlx::query_as("SELECT id, name, created_at, last_used_at FROM passkeys WHERE user_id = ? ORDER BY created_at DESC")
        .bind(auth.user_id).fetch_all(&state.db_pool).await?))
}

#[utoipa::path(post, path = "/api/me/passkeys/register/start", request_body = RegisterInput, responses((status = 200)), tag = "passkeys")]
pub async fn register_start(
    State(state): State<AppState>,
    auth: AuthUser,
    ctx: AuditContext,
    headers: HeaderMap,
    Json(input): Json<RegisterInput>,
) -> Result<Response, LoginError> {
    rate_limit(&state, &ctx).await?;
    let name = input.name.trim();
    if name.is_empty() || name.chars().count() > 100 || name.chars().any(char::is_control) {
        return Err(AppError::InputError(vec![
            "Give your passkey a name of 1–100 characters.".into(),
        ])
        .into());
    }
    let wa = webauthn(&state.origin)?;
    let mut conn = state.db_pool.acquire().await?;
    let user = User::get(auth.user_id, &mut conn)
        .await?
        .ok_or(AppError::AuthenticationRequired)?;
    let ids: Vec<Vec<u8>> =
        sqlx::query_scalar("SELECT credential_id FROM passkeys WHERE user_id = ?")
            .bind(user.id)
            .fetch_all(&mut *conn)
            .await?;
    if ids.len() >= MAX_PASSKEYS as usize {
        return Err(AppError::InputError(vec![
            "Remove a passkey before adding another (limit: 20).".into(),
        ])
        .into());
    }
    let version: i64 =
        sqlx::query_scalar("SELECT token_version FROM users WHERE id = ? AND active = 1")
            .bind(user.id)
            .fetch_one(&mut *conn)
            .await?;
    let (options, registration) = wa
        .start_passkey_registration(
            user.id,
            &user.username,
            &user.name,
            Some(ids.into_iter().map(Into::into).collect()),
        )
        .map_err(|e| AppError::InternalError(e.to_string()))?;
    let mut options =
        serde_json::to_value(options).map_err(|e| AppError::InternalError(e.to_string()))?;
    // Require discoverable credentials for username-free sign-in. Keep both
    // Level 1 and Level 2 fields for older Safari/WebAuthn implementations.
    options["publicKey"]["authenticatorSelection"]["residentKey"] = json!("required");
    options["publicKey"]["authenticatorSelection"]["requireResidentKey"] = json!(true);
    save_challenge(
        &mut conn,
        &headers,
        "register",
        Challenge {
            user_id: Some(user.id),
            token_version: Some(version),
            name: Some(name.into()),
            state: encode(&registration)?,
        },
        options["publicKey"].take(),
    )
    .await
    .map_err(Into::into)
}

#[utoipa::path(post, path = "/api/me/passkeys/register/finish", request_body = Value, responses((status = 201, body = PasskeyInfo)), tag = "passkeys")]
pub async fn register_finish(
    State(state): State<AppState>,
    auth: AuthUser,
    ctx: AuditContext,
    headers: HeaderMap,
    Json(input): Json<Value>,
) -> Result<Response, LoginError> {
    rate_limit(&state, &ctx).await?;
    let mut conn = state.db_pool.acquire().await?;
    let challenge = take_challenge(&mut conn, &headers, "register").await?;
    if challenge.user_id != Some(auth.user_id) {
        return Err(AppError::AuthenticationRequired.into());
    }
    let registration: PasskeyRegistration = decode(&challenge.state)?;
    let credential: RegisterPublicKeyCredential = serde_json::from_value(input)
        .map_err(|_| AppError::InputError(vec!["Invalid passkey response.".into()]))?;
    let passkey = webauthn(&state.origin)?
        .finish_passkey_registration(&credential, &registration)
        .map_err(|_| AppError::AuthenticationRequired)?;
    let mut tx = conn.begin_with("BEGIN IMMEDIATE").await?;
    let version: Option<i64> =
        sqlx::query_scalar("SELECT token_version FROM users WHERE id = ? AND active = 1")
            .bind(auth.user_id)
            .fetch_optional(&mut *tx)
            .await?;
    if version.is_none() || version != challenge.token_version {
        return Err(AppError::AuthenticationRequired.into());
    }
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM passkeys WHERE user_id = ?")
        .bind(auth.user_id)
        .fetch_one(&mut *tx)
        .await?;
    if count >= MAX_PASSKEYS {
        return Err(AppError::InputError(vec!["Passkey limit reached.".into()]).into());
    }
    let info = PasskeyInfo {
        id: Uuid::new_v4(),
        name: challenge.name.unwrap_or_default(),
        created_at: now_epoch(),
        last_used_at: None,
    };
    sqlx::query("INSERT INTO passkeys (id, user_id, credential_id, name, credential, created_at) VALUES (?, ?, ?, ?, ?, ?)")
        .bind(info.id).bind(auth.user_id).bind(passkey.cred_id().as_ref() as &[u8]).bind(&info.name)
        .bind(encode(&passkey)?).bind(info.created_at).execute(&mut *tx).await?;
    audit(AuditEventType::PasskeyCreated)
        .user(auth.user_id)
        .ctx(&ctx)
        .details(json!({"passkey_id": info.id, "name": info.name}))
        .save(&mut tx)
        .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        [(header::SET_COOKIE, challenge_cookie("register", "", 0))],
        Json(info),
    )
        .into_response())
}

#[utoipa::path(post, path = "/api/auth/passkeys/start", responses((status = 200)), tag = "passkeys")]
pub async fn login_start(
    State(state): State<AppState>,
    ctx: AuditContext,
    headers: HeaderMap,
) -> Result<Response, LoginError> {
    rate_limit(&state, &ctx).await?;
    let (options, authentication) = webauthn(&state.origin)?
        .start_discoverable_authentication()
        .map_err(|e| AppError::InternalError(e.to_string()))?;
    let options =
        serde_json::to_value(options).map_err(|e| AppError::InternalError(e.to_string()))?;
    let mut conn = state.db_pool.acquire().await?;
    // Only publicKey is sent: the explicit button uses modal mediation, which
    // works without conditional-autofill support and can offer cross-device QR.
    save_challenge(
        &mut conn,
        &headers,
        "login",
        Challenge {
            user_id: None,
            token_version: None,
            name: None,
            state: encode(&authentication)?,
        },
        options["publicKey"].clone(),
    )
    .await
    .map_err(Into::into)
}

#[utoipa::path(post, path = "/api/auth/passkeys/finish", request_body = Value, responses((status = 200)), tag = "passkeys")]
pub async fn login_finish(
    State(state): State<AppState>,
    ctx: AuditContext,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<BrowserLoginQuery>,
    Json(input): Json<Value>,
) -> Result<Response, LoginError> {
    rate_limit(&state, &ctx).await?;
    let mut conn = state.db_pool.acquire().await?;
    let challenge = take_challenge(&mut conn, &headers, "login").await?;
    let authentication: DiscoverableAuthentication = decode(&challenge.state)?;
    let credential: PublicKeyCredential =
        serde_json::from_value(input).map_err(|_| AppError::AuthenticationRequired)?;
    let wa = webauthn(&state.origin)?;
    let (user_id, credential_id) = wa
        .identify_discoverable_authentication(&credential)
        .map_err(|_| AppError::AuthenticationRequired)?;
    // Hold a write transaction while checking/updating counters and issuing the
    // session: concurrent deletion/deactivation cannot race authentication.
    let mut tx = conn.begin_with("BEGIN IMMEDIATE").await?;
    let stored: Option<(Uuid, String)> = sqlx::query_as("SELECT p.id, p.credential FROM passkeys p JOIN users u ON u.id = p.user_id WHERE p.user_id = ? AND p.credential_id = ? AND u.active = 1")
        .bind(user_id).bind(credential_id).fetch_optional(&mut *tx).await?;
    let Some((id, stored)) = stored else {
        return Err(AppError::AuthenticationRequired.into());
    };
    let mut passkey: Passkey = decode(&stored)?;
    let result = match wa.finish_discoverable_authentication(
        &credential,
        authentication,
        &[DiscoverableKey::from(&passkey)],
    ) {
        Ok(result) if result.user_verified() => result,
        _ => {
            audit(AuditEventType::LoginFailed)
                .user(user_id)
                .ctx(&ctx)
                .details(json!({"method": "passkey"}))
                .save(&mut tx)
                .await?;
            tx.commit().await?;
            return Err(AppError::AuthenticationRequired.into());
        }
    };
    passkey.update_credential(&result);
    sqlx::query("UPDATE passkeys SET credential = ?, last_used_at = ? WHERE id = ?")
        .bind(encode(&passkey)?)
        .bind(now_epoch())
        .bind(id)
        .execute(&mut *tx)
        .await?;
    let user = User::get(user_id, &mut tx)
        .await?
        .ok_or(AppError::AuthenticationRequired)?;
    let roles = user.get_roles(&mut tx).await?;
    // Verified passkeys already satisfy MFA. Do not invoke password/TOTP enforcement.
    let pair = token::generate_token_pair(user_id, roles, &state.signing_key, &mut tx).await?;
    audit(AuditEventType::LoginSuccess)
        .user(user_id)
        .ctx(&ctx)
        .details(json!({"method": "passkey", "passkey_id": id}))
        .save(&mut tx)
        .await?;
    tx.commit().await?;
    let mut response = browser_login_response(&pair, query)?;
    response.headers_mut().append(
        header::SET_COOKIE,
        challenge_cookie("login", "", 0).parse().unwrap(),
    );
    Ok(response)
}

#[utoipa::path(delete, path = "/api/me/passkeys/{id}", params(("id" = Uuid, Path)), responses((status = 204)), tag = "passkeys")]
pub async fn delete(
    State(state): State<AppState>,
    auth: AuthUser,
    ctx: AuditContext,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let mut tx = state.db_pool.begin().await?;
    let deleted = sqlx::query("DELETE FROM passkeys WHERE id = ? AND user_id = ?")
        .bind(id)
        .bind(auth.user_id)
        .execute(&mut *tx)
        .await?;
    if deleted.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    // Removing a lost credential also invalidates sessions it may have created.
    token::revoke_all_user_tokens(auth.user_id, &mut tx).await?;
    sqlx::query("DELETE FROM passkey_challenges WHERE user_id = ?")
        .bind(auth.user_id)
        .execute(&mut *tx)
        .await?;
    audit(AuditEventType::PasskeyDeleted)
        .user(auth.user_id)
        .ctx(&ctx)
        .details(json!({"passkey_id": id}))
        .save(&mut tx)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

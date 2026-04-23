use axum::extract::{self, Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use tracing::info;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::AppState;
use crate::audit::{AuditContext, AuditEventType, AuditLogEntry};
use crate::auth_middleware::{AdminUser, AuthUser};
use crate::db::DbEntity;
use crate::errors::AppError;
use crate::user::User;
use crate::user::auth::Authenticator;
use crate::user::auth::totp::{self, UserTotp};

const TOTP_TAG: &str = "totp";
const DEFAULT_ISSUER: &str = "Authere";

#[derive(Debug, Serialize, ToSchema)]
pub struct TotpStatus {
    /// True when the user has an active, verified TOTP enrolled.
    pub enabled: bool,
    /// True when there is a pending enrollment awaiting first-code verification.
    pub pending: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct EnrollResponse {
    /// Raw Base32-encoded secret. Shown once during enrollment so the user can key it in
    /// manually if QR scanning isn't available.
    pub secret: String,
    /// Full `otpauth://totp/…` URI suitable for QR-code encoding.
    pub otpauth_uri: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ActivateInput {
    /// 6-digit code from the authenticator app.
    pub code: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ActivateResponse {
    /// Plain-text recovery codes, shown exactly once. The server stores only their hashes.
    pub recovery_codes: Vec<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct DisableInput {
    /// Current account password — required to disable MFA to prevent session-hijack bypass.
    pub current_password: String,
}

async fn audit_mfa(
    event_type: AuditEventType,
    user_id: Uuid,
    actor_id: Option<Uuid>,
    ctx: &AuditContext,
    conn: &mut sqlx::SqliteConnection,
) {
    let mut entry = AuditLogEntry::new(event_type).user(user_id).ip(&ctx.ip_address);
    if let Some(a) = actor_id {
        entry = entry.actor(a);
    }
    if let Some(ref ua) = ctx.user_agent {
        entry = entry.user_agent(ua);
    }
    let _ = entry.save(conn).await;
}

#[utoipa::path(
    get,
    path = "/api/me/totp",
    responses(
        (status = 200, description = "TOTP status for the current user", body = TotpStatus),
        (status = 401, description = "Authentication required"),
    ),
    tag = TOTP_TAG,
)]
pub async fn get_my_totp_status(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<axum::Json<TotpStatus>, AppError> {
    let mut conn = state.db_pool.acquire().await?;
    let row = UserTotp::get(auth.user_id, &mut conn).await?;
    let (enabled, pending) = match row {
        None => (false, false),
        Some(t) if t.is_activated() => (true, false),
        Some(_) => (false, true),
    };
    Ok(axum::Json(TotpStatus { enabled, pending }))
}

#[utoipa::path(
    post,
    path = "/api/me/totp/enroll",
    responses(
        (status = 200, description = "Enrollment started — show QR and await activation", body = EnrollResponse),
        (status = 401, description = "Authentication required"),
        (status = 409, description = "TOTP already enabled — disable it first to re-enroll"),
    ),
    tag = TOTP_TAG,
)]
pub async fn enroll_my_totp(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<axum::Json<EnrollResponse>, AppError> {
    let mut conn = state.db_pool.acquire().await?;
    let existing = UserTotp::get(auth.user_id, &mut conn).await?;
    if matches!(existing, Some(ref t) if t.is_activated()) {
        return Err(AppError::UniqueError(
            "TOTP is already enabled. Disable it first to re-enroll.".into(),
        ));
    }

    let user = User::get(auth.user_id, &mut conn).await?.ok_or(AppError::NotFound)?;
    let secret = totp::generate_secret();
    let encrypted = totp::encrypt_secret(&secret)?;
    UserTotp::upsert_pending(auth.user_id, &encrypted, &mut conn).await?;

    let issuer = std::env::var("AUTHERE_TOTP_ISSUER").unwrap_or_else(|_| DEFAULT_ISSUER.to_string());
    let otpauth_uri = totp::build_otpauth_uri(&issuer, &user.username, &secret);
    let secret_b32 = totp::encode_base32(&secret);

    info!(user_id = %auth.user_id, "totp enrollment started");
    Ok(axum::Json(EnrollResponse {
        secret: secret_b32,
        otpauth_uri,
    }))
}

#[utoipa::path(
    post,
    path = "/api/me/totp/activate",
    request_body(content = ActivateInput),
    responses(
        (status = 200, description = "Activated — store the returned recovery codes", body = ActivateResponse),
        (status = 400, description = "Invalid input or no pending enrollment"),
        (status = 401, description = "Authentication required or code did not match"),
    ),
    tag = TOTP_TAG,
)]
pub async fn activate_my_totp(
    State(state): State<AppState>,
    audit_ctx: AuditContext,
    auth: AuthUser,
    extract::Json(input): extract::Json<ActivateInput>,
) -> Result<axum::Json<ActivateResponse>, AppError> {
    let mut conn = state.db_pool.acquire().await?;
    let pending = UserTotp::get(auth.user_id, &mut conn)
        .await?
        .filter(|t| !t.is_activated())
        .ok_or_else(|| AppError::InputError(vec!["No pending TOTP enrollment".into()]))?;

    let secret = totp::decrypt_secret(&pending.secret_encrypted)?;
    let now = totp::now_epoch();
    let step = totp::verify_code(&secret, &input.code, now, None)
        .ok_or(AppError::AuthenticationRequired)?;

    UserTotp::activate(auth.user_id, step, &mut conn).await?;
    let recovery_codes = totp::generate_recovery_codes();
    totp::store_recovery_codes(auth.user_id, &recovery_codes, &mut conn).await?;

    audit_mfa(AuditEventType::MfaEnabled, auth.user_id, None, &audit_ctx, &mut conn).await;
    info!(user_id = %auth.user_id, "totp activated");

    Ok(axum::Json(ActivateResponse { recovery_codes }))
}

#[utoipa::path(
    delete,
    path = "/api/me/totp",
    request_body(content = DisableInput),
    responses(
        (status = 204, description = "TOTP disabled"),
        (status = 401, description = "Authentication required or wrong password"),
        (status = 404, description = "TOTP not enabled"),
    ),
    tag = TOTP_TAG,
)]
pub async fn disable_my_totp(
    State(state): State<AppState>,
    audit_ctx: AuditContext,
    auth: AuthUser,
    extract::Json(input): extract::Json<DisableInput>,
) -> Result<StatusCode, AppError> {
    let mut conn = state.db_pool.acquire().await?;
    let user = User::get(auth.user_id, &mut conn).await?.ok_or(AppError::NotFound)?;
    Authenticator::try_password_login(&user, input.current_password, &mut conn).await?;

    let deleted = UserTotp::delete(auth.user_id, &mut conn).await?;
    if !deleted {
        return Err(AppError::NotFound);
    }

    audit_mfa(AuditEventType::MfaDisabled, auth.user_id, None, &audit_ctx, &mut conn).await;
    info!(user_id = %auth.user_id, "totp disabled by user");
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete,
    path = "/api/user/{id}/totp",
    params(("id" = Uuid, Path, description = "User ID")),
    responses(
        (status = 204, description = "TOTP disabled for the target user"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin access required"),
        (status = 404, description = "TOTP not enabled for this user"),
    ),
    tag = TOTP_TAG,
)]
pub async fn admin_disable_user_totp(
    State(state): State<AppState>,
    audit_ctx: AuditContext,
    admin: AdminUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let mut conn = state.db_pool.acquire().await?;
    User::get(id, &mut conn).await?.ok_or(AppError::NotFound)?;

    let deleted = UserTotp::delete(id, &mut conn).await?;
    if !deleted {
        return Err(AppError::NotFound);
    }

    audit_mfa(
        AuditEventType::MfaDisabled,
        id,
        Some(admin.0.user_id),
        &audit_ctx,
        &mut conn,
    )
    .await;
    info!(user_id = %id, admin = %admin.0.user_id, "admin force-disabled totp");
    Ok(StatusCode::NO_CONTENT)
}

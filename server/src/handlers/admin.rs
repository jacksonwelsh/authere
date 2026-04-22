use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use rand::Rng;
use serde::{Deserialize, Serialize};
use tracing::info;
use uuid::Uuid;

use crate::AppState;
use crate::audit::{
    AuditContext, AuditLogQuery, AuditLogRecord, log_invitation_created, log_invitation_deleted,
    log_ldap_bind_password_rotated, log_settings_updated,
};
use crate::auth_middleware::AdminUser;
use crate::errors::AppError;
use crate::invitation::{CreateInvitationInput, Invitation, InvitationWithStatus};
use crate::settings::{
    KEY_LDAP_BASE_DN, KEY_LDAP_BIND_ADDRESS, KEY_LDAP_ENABLED, KEY_LDAP_PASSWORD_MODE,
    KEY_LDAP_SERVICE_PASSWORD_HASH, KEY_OPEN_REGISTRATION, LdapSettingsInput, SettingsResponse,
    UpdateSettingsInput, load_ldap_config, open_registration_enabled, set_setting,
    to_ldap_settings, validate_base_dn, validate_bind_address,
};

const ADMIN_TAG: &str = "admin";

#[derive(Deserialize)]
pub struct AuditLogParams {
    limit: Option<i64>,
    offset: Option<i64>,
    user_id: Option<Uuid>,
    since: Option<i64>,
    until: Option<i64>,
}

#[utoipa::path(
    get,
    path = "/api/audit",
    responses(
        (status = 200, description = "Audit log entries"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin required"),
    ),
    tag = ADMIN_TAG,
)]
pub async fn get_audit_log(
    _admin: AdminUser,
    State(state): State<AppState>,
    Query(params): Query<AuditLogParams>,
) -> Result<axum::Json<Vec<AuditLogRecord>>, AppError> {
    let limit = params.limit.unwrap_or(50).clamp(1, 200);
    let offset = params.offset.unwrap_or(0).max(0);

    let mut query = AuditLogQuery::new().limit(limit).offset(offset);
    if let Some(uid) = params.user_id {
        query = query.for_user(uid);
    }
    if let Some(ts) = params.since {
        query = query.since(ts);
    }
    if let Some(ts) = params.until {
        query = query.until(ts);
    }

    let mut conn = state.db_pool.acquire().await?;
    let records = query.execute(&mut conn).await?;
    Ok(axum::Json(records))
}

// ============================================================================
// Settings
// ============================================================================

#[utoipa::path(
    get,
    path = "/api/settings",
    responses(
        (status = 200, description = "Current system settings", body = SettingsResponse),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin required"),
    ),
    tag = ADMIN_TAG,
)]
pub async fn get_settings(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<axum::Json<SettingsResponse>, AppError> {
    let mut conn = state.db_pool.acquire().await?;
    let open_registration = open_registration_enabled(&mut conn).await?;
    let ldap_cfg = load_ldap_config(&mut conn).await?;
    Ok(axum::Json(SettingsResponse {
        open_registration,
        ldap: to_ldap_settings(&ldap_cfg),
    }))
}

#[utoipa::path(
    patch,
    path = "/api/settings",
    request_body(content = UpdateSettingsInput),
    responses(
        (status = 200, description = "Updated settings", body = SettingsResponse),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin required"),
    ),
    tag = ADMIN_TAG,
)]
pub async fn update_settings(
    State(state): State<AppState>,
    audit_ctx: AuditContext,
    admin: AdminUser,
    axum::extract::Json(input): axum::extract::Json<UpdateSettingsInput>,
) -> Result<axum::Json<SettingsResponse>, AppError> {
    let mut conn = state.db_pool.acquire().await?;

    let mut changes = serde_json::json!({});

    if let Some(open_reg) = input.open_registration {
        let val = if open_reg { "true" } else { "false" };
        set_setting(KEY_OPEN_REGISTRATION, val, &mut conn).await?;
        changes["open_registration"] = serde_json::json!(open_reg);
        info!(admin = %admin.0.user_id, open_registration = open_reg, "settings updated");
    }

    if let Some(ldap) = input.ldap {
        apply_ldap_input(&ldap, &mut changes, &mut conn).await?;
    }

    let _ = log_settings_updated(admin.0.user_id, changes, &audit_ctx, &mut conn).await;

    let open_registration = open_registration_enabled(&mut conn).await?;
    let ldap_cfg = load_ldap_config(&mut conn).await?;
    Ok(axum::Json(SettingsResponse {
        open_registration,
        ldap: to_ldap_settings(&ldap_cfg),
    }))
}

async fn apply_ldap_input(
    input: &LdapSettingsInput,
    changes: &mut serde_json::Value,
    conn: &mut sqlx::SqliteConnection,
) -> Result<(), AppError> {
    let mut ldap_changes = serde_json::json!({});

    if let Some(enabled) = input.enabled {
        let val = if enabled { "true" } else { "false" };
        set_setting(KEY_LDAP_ENABLED, val, conn).await?;
        ldap_changes["enabled"] = serde_json::json!(enabled);
    }

    if let Some(ref base_dn) = input.base_dn {
        validate_base_dn(base_dn).map_err(|e| AppError::InputError(vec![e]))?;
        set_setting(KEY_LDAP_BASE_DN, base_dn.trim(), conn).await?;
        ldap_changes["base_dn"] = serde_json::json!(base_dn.trim());
    }

    if let Some(ref bind_address) = input.bind_address {
        validate_bind_address(bind_address).map_err(|e| AppError::InputError(vec![e]))?;
        set_setting(KEY_LDAP_BIND_ADDRESS, bind_address.trim(), conn).await?;
        ldap_changes["bind_address"] = serde_json::json!(bind_address.trim());
    }

    if let Some(mode) = input.password_mode {
        set_setting(KEY_LDAP_PASSWORD_MODE, mode.as_str(), conn).await?;
        ldap_changes["password_mode"] = serde_json::json!(mode.as_str());
    }

    if !ldap_changes.as_object().map(|o| o.is_empty()).unwrap_or(true) {
        changes["ldap"] = ldap_changes;
    }
    Ok(())
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RegenerateLdapPasswordResponse {
    pub password: String,
}

/// Generate a random service-account bind password, store its hash, and return the cleartext
/// once. Rotates any previously set password; active Jellyfin/other integrations will need to
/// be reconfigured.
#[utoipa::path(
    post,
    path = "/api/settings/ldap/regenerate-bind-password",
    responses(
        (status = 200, description = "New bind password, returned once", body = RegenerateLdapPasswordResponse),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin required"),
    ),
    tag = ADMIN_TAG,
)]
pub async fn regenerate_ldap_bind_password(
    State(state): State<AppState>,
    audit_ctx: AuditContext,
    admin: AdminUser,
) -> Result<axum::Json<RegenerateLdapPasswordResponse>, AppError> {
    let password = generate_service_password();
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
        .map_err(|e| AppError::InternalError(format!("Failed to hash password: {e}")))?
        .to_string();

    let mut conn = state.db_pool.acquire().await?;
    set_setting(KEY_LDAP_SERVICE_PASSWORD_HASH, &hash, &mut conn).await?;

    info!(admin = %admin.0.user_id, "ldap service bind password rotated");
    let _ = log_ldap_bind_password_rotated(admin.0.user_id, &audit_ctx, &mut conn).await;

    Ok(axum::Json(RegenerateLdapPasswordResponse { password }))
}

fn generate_service_password() -> String {
    const CHARS: &[u8] =
        b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
    let mut rng = rand::thread_rng();
    (0..32)
        .map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char)
        .collect()
}

// ============================================================================
// Invitations
// ============================================================================

#[utoipa::path(
    get,
    path = "/api/invitations",
    responses(
        (status = 200, description = "List of invitations"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin required"),
    ),
    tag = ADMIN_TAG,
)]
pub async fn list_invitations(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<axum::Json<Vec<InvitationWithStatus>>, AppError> {
    let mut conn = state.db_pool.acquire().await?;
    let invitations = Invitation::list(&mut conn).await?;
    Ok(axum::Json(invitations))
}

#[utoipa::path(
    post,
    path = "/api/invitations",
    request_body(content = CreateInvitationInput),
    responses(
        (status = 201, description = "Created invitation"),
        (status = 400, description = "Invalid input"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin required"),
    ),
    tag = ADMIN_TAG,
)]
pub async fn create_invitation(
    State(state): State<AppState>,
    audit_ctx: AuditContext,
    admin: AdminUser,
    axum::extract::Json(input): axum::extract::Json<CreateInvitationInput>,
) -> Result<(StatusCode, axum::Json<Invitation>), AppError> {
    Invitation::validate_input(&input)?;

    let invitation = Invitation::new(input, admin.0.user_id);
    let mut conn = state.db_pool.acquire().await?;
    invitation.save(&mut conn).await?;

    info!(admin = %admin.0.user_id, invite_id = %invitation.id, label = ?invitation.label, "invitation created");
    let _ = log_invitation_created(admin.0.user_id, &invitation.id, invitation.label.as_deref(), &audit_ctx, &mut conn).await;

    Ok((StatusCode::CREATED, axum::Json(invitation)))
}

#[utoipa::path(
    delete,
    path = "/api/invitations/{id}",
    params(
        ("id" = String, Path, description = "Invitation ID")
    ),
    responses(
        (status = 204, description = "Invitation deleted"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin required"),
        (status = 404, description = "Invitation not found"),
    ),
    tag = ADMIN_TAG,
)]
pub async fn delete_invitation(
    State(state): State<AppState>,
    audit_ctx: AuditContext,
    admin: AdminUser,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    let mut conn = state.db_pool.acquire().await?;

    let deleted = Invitation::delete(&id, &mut conn).await?;
    if !deleted {
        return Err(AppError::NotFound);
    }

    info!(admin = %admin.0.user_id, invite_id = %id, "invitation deleted");
    let _ = log_invitation_deleted(admin.0.user_id, &id, &audit_ctx, &mut conn).await;

    Ok(StatusCode::NO_CONTENT)
}

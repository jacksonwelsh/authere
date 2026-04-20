use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use serde::Deserialize;
use tracing::info;
use uuid::Uuid;

use crate::AppState;
use crate::audit::{AuditContext, AuditLogQuery, AuditLogRecord, log_invitation_created, log_invitation_deleted, log_settings_updated};
use crate::auth_middleware::AdminUser;
use crate::errors::AppError;
use crate::invitation::{CreateInvitationInput, Invitation, InvitationWithStatus};
use crate::settings::{SettingsResponse, UpdateSettingsInput, open_registration_enabled, set_setting};

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
    Ok(axum::Json(SettingsResponse { open_registration }))
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
        set_setting("open_registration", val, &mut conn).await?;
        changes["open_registration"] = serde_json::json!(open_reg);
        info!(admin = %admin.0.user_id, open_registration = open_reg, "settings updated");
    }

    let _ = log_settings_updated(admin.0.user_id, changes, &audit_ctx, &mut conn).await;

    let open_registration = open_registration_enabled(&mut conn).await?;
    Ok(axum::Json(SettingsResponse { open_registration }))
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

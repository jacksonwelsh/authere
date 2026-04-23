use axum::extract::{Path, State};
use axum::http::StatusCode;
use tracing::info;
use uuid::Uuid;

use crate::AppState;
use crate::app_passwords::{AppPassword, CreateAppPasswordInput, CreateAppPasswordResponse};
use crate::audit::{audit, AuditContext, AuditEventType};
use crate::auth_middleware::{AdminUser, AuthUser};
use crate::errors::AppError;
use crate::settings::load_ldap_config;

const APP_PW_TAG: &str = "app_passwords";

#[utoipa::path(
    get,
    path = "/api/me/app-passwords",
    responses(
        (status = 200, description = "List of the user's app passwords"),
        (status = 401, description = "Authentication required"),
    ),
    tag = APP_PW_TAG,
)]
pub async fn list_my_app_passwords(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<axum::Json<Vec<AppPassword>>, AppError> {
    let mut conn = state.db_pool.acquire().await?;
    let items = AppPassword::list_for_user(auth.user_id, &mut conn).await?;
    Ok(axum::Json(items))
}

#[utoipa::path(
    post,
    path = "/api/me/app-passwords",
    request_body(content = CreateAppPasswordInput),
    responses(
        (status = 201, description = "Newly created app password, with cleartext"),
        (status = 400, description = "Invalid input"),
        (status = 401, description = "Authentication required"),
        (status = 409, description = "App passwords are disabled in the current LDAP password mode"),
    ),
    tag = APP_PW_TAG,
)]
pub async fn create_my_app_password(
    State(state): State<AppState>,
    audit_ctx: AuditContext,
    auth: AuthUser,
    axum::extract::Json(input): axum::extract::Json<CreateAppPasswordInput>,
) -> Result<(StatusCode, axum::Json<CreateAppPasswordResponse>), AppError> {
    let mut conn = state.db_pool.acquire().await?;

    let ldap_cfg = load_ldap_config(&mut conn).await?;
    if !ldap_cfg.password_mode.app_passwords_enabled() {
        return Err(AppError::UniqueError(
            "App passwords are disabled in the current LDAP password mode".to_string(),
        ));
    }

    let (record, cleartext) = AppPassword::create(auth.user_id, &input.name, &mut conn).await?;
    info!(user_id = %auth.user_id, app_password_id = %record.id, "app password created");
    let _ = audit(AuditEventType::AppPasswordCreated)
        .user(auth.user_id)
        .ctx(&audit_ctx)
        .details(serde_json::json!({ "app_password_id": record.id, "name": record.name }))
        .save(&mut conn)
        .await;
    Ok((
        StatusCode::CREATED,
        axum::Json(CreateAppPasswordResponse {
            app_password: record,
            password: cleartext,
        }),
    ))
}

#[utoipa::path(
    delete,
    path = "/api/me/app-passwords/{id}",
    params(("id" = Uuid, Path, description = "App password ID")),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Not found"),
    ),
    tag = APP_PW_TAG,
)]
pub async fn delete_my_app_password(
    State(state): State<AppState>,
    audit_ctx: AuditContext,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let mut conn = state.db_pool.acquire().await?;
    let deleted = AppPassword::delete_for_user(id, auth.user_id, &mut conn).await?;
    if !deleted {
        return Err(AppError::NotFound);
    }
    info!(user_id = %auth.user_id, app_password_id = %id, "app password deleted");
    let _ = audit(AuditEventType::AppPasswordDeleted)
        .user(auth.user_id)
        .ctx(&audit_ctx)
        .details(serde_json::json!({ "app_password_id": id }))
        .save(&mut conn)
        .await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/api/users/{user_id}/app-passwords",
    params(("user_id" = Uuid, Path, description = "User ID")),
    responses(
        (status = 200, description = "List of the user's app passwords"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin required"),
    ),
    tag = APP_PW_TAG,
)]
pub async fn admin_list_app_passwords(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(user_id): Path<Uuid>,
) -> Result<axum::Json<Vec<AppPassword>>, AppError> {
    let mut conn = state.db_pool.acquire().await?;
    let items = AppPassword::list_for_user(user_id, &mut conn).await?;
    Ok(axum::Json(items))
}

#[utoipa::path(
    delete,
    path = "/api/users/{user_id}/app-passwords/{id}",
    params(
        ("user_id" = Uuid, Path, description = "User ID"),
        ("id" = Uuid, Path, description = "App password ID"),
    ),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin required"),
        (status = 404, description = "Not found"),
    ),
    tag = APP_PW_TAG,
)]
pub async fn admin_delete_app_password(
    State(state): State<AppState>,
    audit_ctx: AuditContext,
    admin: AdminUser,
    Path((user_id, id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    let mut conn = state.db_pool.acquire().await?;
    let deleted = AppPassword::delete_for_user(id, user_id, &mut conn).await?;
    if !deleted {
        return Err(AppError::NotFound);
    }
    info!(
        admin = %admin.0.user_id,
        user_id = %user_id,
        app_password_id = %id,
        "admin revoked app password"
    );
    let _ = audit(AuditEventType::AdminAppPasswordDeleted)
        .user(user_id)
        .actor(admin.0.user_id)
        .ctx(&audit_ctx)
        .details(serde_json::json!({ "app_password_id": id }))
        .save(&mut conn)
        .await;
    Ok(StatusCode::NO_CONTENT)
}

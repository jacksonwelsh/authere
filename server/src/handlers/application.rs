use axum::extract::{self, Path, State};
use axum::http::StatusCode;
use serde::Serialize;
use tracing::info;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::AppState;
use crate::application::{AppType, Application, CreateApplicationInput, UpdateApplicationInput};
use crate::audit::{AuditContext, AuditEventType, audit};
use crate::auth_middleware::AdminUser;
use crate::db::DbEntity;
use crate::errors::AppError;

const ADMIN_TAG: &str = "admin";

/// Response for `POST /api/applications`. Extends the base `Application` with the one-time
/// plaintext `oidc_client_secret` field for freshly-created confidential OIDC clients.
#[derive(Debug, Serialize, ToSchema)]
pub struct CreateApplicationResponse {
    #[serde(flatten)]
    pub application: Application,
    /// Present only when an OIDC confidential client is created. Displayed once and never
    /// again — the server only stores its hash after this response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oidc_client_secret: Option<String>,
}

#[utoipa::path(
    get,
    path = "/api/applications",
    responses(
        (status = 200, description = "List all applications", body = Vec<Application>),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin access required"),
        (status = 500, description = "Internal server error")
    ),
    tag = ADMIN_TAG,
)]
pub async fn list_applications(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<axum::Json<Vec<Application>>, AppError> {
    let mut conn = state.db_pool.acquire().await?;
    let apps = Application::list(&mut conn).await?;
    Ok(axum::Json(apps))
}

#[utoipa::path(
    post,
    path = "/api/applications",
    request_body(content = CreateApplicationInput),
    responses(
        (status = 201, description = "Application created", body = CreateApplicationResponse),
        (status = 400, description = "Invalid input"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin access required"),
        (status = 409, description = "Application with that slug already exists"),
        (status = 500, description = "Internal server error")
    ),
    tag = ADMIN_TAG,
)]
pub async fn create_application(
    State(state): State<AppState>,
    audit_ctx: AuditContext,
    admin: AdminUser,
    extract::Json(input): extract::Json<CreateApplicationInput>,
) -> Result<(StatusCode, axum::Json<CreateApplicationResponse>), AppError> {
    Application::validate_input(&input)?;

    let app_type = input.app_type.unwrap_or(AppType::ForwardAuth);
    let (app, plaintext_secret) = match app_type {
        AppType::ForwardAuth => (Application::new(input), None),
        AppType::Oidc => Application::new_oidc(input),
    };

    let mut conn = state.db_pool.acquire().await?;
    app.save(&mut conn).await?;

    info!(
        app_id = %app.id,
        app_name = %app.name,
        slug = %app.slug,
        app_type = app.app_type.as_str(),
        "application created"
    );
    let _ = audit(AuditEventType::ApplicationCreated)
        .actor(admin.0.user_id)
        .ctx(&audit_ctx)
        .details(serde_json::json!({
            "application_id": app.id,
            "name": app.name,
            "slug": app.slug,
            "app_type": app.app_type.as_str(),
        }))
        .save(&mut conn)
        .await;

    Ok((
        StatusCode::CREATED,
        axum::Json(CreateApplicationResponse {
            application: app,
            oidc_client_secret: plaintext_secret,
        }),
    ))
}

#[utoipa::path(
    get,
    path = "/api/applications/{id}",
    params(
        ("id" = Uuid, Path, description = "Application ID")
    ),
    responses(
        (status = 200, description = "Application details", body = Application),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin access required"),
        (status = 404, description = "Application not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = ADMIN_TAG,
)]
pub async fn get_application(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(id): Path<Uuid>,
) -> Result<axum::Json<Application>, AppError> {
    let mut conn = state.db_pool.acquire().await?;
    let app = Application::get(id, &mut conn).await?;

    match app {
        Some(app) => Ok(axum::Json(app)),
        None => Err(AppError::NotFound),
    }
}

#[utoipa::path(
    put,
    path = "/api/applications/{id}",
    params(
        ("id" = Uuid, Path, description = "Application ID")
    ),
    request_body(content = UpdateApplicationInput),
    responses(
        (status = 200, description = "Application updated", body = Application),
        (status = 400, description = "Invalid input"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin access required"),
        (status = 404, description = "Application not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = ADMIN_TAG,
)]
pub async fn update_application(
    State(state): State<AppState>,
    audit_ctx: AuditContext,
    admin: AdminUser,
    Path(id): Path<Uuid>,
    extract::Json(input): extract::Json<UpdateApplicationInput>,
) -> Result<axum::Json<Application>, AppError> {
    let mut conn = state.db_pool.acquire().await?;
    let mut app = Application::get(id, &mut conn)
        .await?
        .ok_or(AppError::NotFound)?;

    app.update(input, &mut conn).await?;
    info!(app_id = %id, app_name = %app.name, "application updated");
    let _ = audit(AuditEventType::ApplicationUpdated)
        .actor(admin.0.user_id)
        .ctx(&audit_ctx)
        .details(serde_json::json!({
            "application_id": app.id,
            "name": app.name,
            "slug": app.slug,
        }))
        .save(&mut conn)
        .await;
    Ok(axum::Json(app))
}

#[utoipa::path(
    delete,
    path = "/api/applications/{id}",
    params(
        ("id" = Uuid, Path, description = "Application ID")
    ),
    responses(
        (status = 204, description = "Application deleted"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin access required"),
        (status = 404, description = "Application not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = ADMIN_TAG,
)]
pub async fn delete_application(
    State(state): State<AppState>,
    audit_ctx: AuditContext,
    admin: AdminUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let mut conn = state.db_pool.acquire().await?;

    let existing = Application::get(id, &mut conn).await?;
    let deleted = Application::delete(id, &mut conn).await?;
    if deleted {
        info!(app_id = %id, "application deleted");
        let details = match existing {
            Some(app) => serde_json::json!({
                "application_id": id,
                "name": app.name,
                "slug": app.slug,
            }),
            None => serde_json::json!({ "application_id": id }),
        };
        let _ = audit(AuditEventType::ApplicationDeleted)
            .actor(admin.0.user_id)
            .ctx(&audit_ctx)
            .details(details)
            .save(&mut conn)
            .await;
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AppError::NotFound)
    }
}

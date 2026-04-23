//! Admin-facing CRUD for provisioning targets and job observability. Lives under
//! `/api/provisioning/*` and uses the JWT-based `AdminUser` extractor — it is NOT part of
//! the `/scim/v2` surface.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::AppState;
use crate::auth_middleware::AdminUser;
use crate::errors::AppError;
use crate::provisioning::{jobs, targets};

const TAG: &str = "provisioning-admin";

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateTargetInput {
    pub name: String,
    /// One of: `generic_scim`. Other values reserved for future adapters.
    pub kind: String,
    pub base_url: String,
    /// Bearer token handed to the downstream target. Stored AES-GCM encrypted; never echoed.
    pub auth_token: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

#[derive(Debug, Deserialize, ToSchema, Default)]
pub struct UpdateTargetInput {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub base_url: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    /// If supplied, rotates the stored token. Otherwise the existing ciphertext is preserved.
    #[serde(default)]
    pub auth_token: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TargetSummary {
    pub id: Uuid,
    pub name: String,
    pub kind: String,
    pub base_url: String,
    pub enabled: bool,
    pub created_at: i64,
    pub created_by: Option<Uuid>,
    pub updated_at: i64,
}

impl From<targets::ProvisioningTarget> for TargetSummary {
    fn from(t: targets::ProvisioningTarget) -> Self {
        Self {
            id: t.id,
            name: t.name,
            kind: t.kind,
            base_url: t.base_url,
            enabled: t.enabled,
            created_at: t.created_at,
            created_by: t.created_by,
            updated_at: t.updated_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct JobSummary {
    pub id: Uuid,
    pub target_id: Uuid,
    pub user_id: Uuid,
    pub event_type: String,
    pub status: String,
    pub attempts: i64,
    pub next_attempt_at: i64,
    pub last_error: Option<String>,
    pub last_response_status: Option<i64>,
    pub external_resource_id: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl From<jobs::OutboundJob> for JobSummary {
    fn from(j: jobs::OutboundJob) -> Self {
        Self {
            id: j.id,
            target_id: j.target_id,
            user_id: j.user_id,
            event_type: j.event_type,
            status: j.status,
            attempts: j.attempts,
            next_attempt_at: j.next_attempt_at,
            last_error: j.last_error,
            last_response_status: j.last_response_status,
            external_resource_id: j.external_resource_id,
            created_at: j.created_at,
            updated_at: j.updated_at,
        }
    }
}

fn validate_kind(kind: &str) -> Result<(), AppError> {
    match kind {
        targets::KIND_GENERIC_SCIM => Ok(()),
        other => Err(AppError::InputError(vec![format!(
            "unknown target kind '{other}'"
        )])),
    }
}

fn validate_base_url(url: &str) -> Result<(), AppError> {
    let parsed = url::Url::parse(url)
        .map_err(|e| AppError::InputError(vec![format!("invalid base_url: {e}")]))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(AppError::InputError(vec![
            "base_url scheme must be http or https".into(),
        ]));
    }
    Ok(())
}

fn validate_name(name: &str) -> Result<(), AppError> {
    let t = name.trim();
    if t.is_empty() || t.len() > 128 {
        return Err(AppError::InputError(vec![
            "target name must be 1-128 characters".into(),
        ]));
    }
    Ok(())
}

#[utoipa::path(
    post,
    path = "/api/provisioning/targets",
    request_body = CreateTargetInput,
    responses(
        (status = 201, description = "Target created", body = TargetSummary),
        (status = 400, description = "Invalid input"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin access required"),
        (status = 500, description = "Encryption key not configured"),
    ),
    tag = TAG,
)]
pub async fn create_target(
    State(state): State<AppState>,
    admin: AdminUser,
    Json(input): Json<CreateTargetInput>,
) -> Result<(StatusCode, Json<TargetSummary>), AppError> {
    validate_name(&input.name)?;
    validate_kind(&input.kind)?;
    validate_base_url(&input.base_url)?;
    if input.auth_token.trim().is_empty() {
        return Err(AppError::InputError(vec![
            "auth_token is required".into(),
        ]));
    }

    let key = targets::load_master_key()?;
    let mut conn = state.db_pool.acquire().await?;
    let created = targets::create(
        input.name.trim(),
        &input.kind,
        input.base_url.trim(),
        &input.auth_token,
        input.enabled,
        Some(admin.0.user_id),
        &key,
        &mut conn,
    )
    .await?;
    // Poke the worker in case this is a new target with pending jobs (unlikely — none yet —
    // but cheap).
    state.provisioning_notifier.notify_one();
    Ok((StatusCode::CREATED, Json(created.into())))
}

#[utoipa::path(
    get,
    path = "/api/provisioning/targets",
    responses(
        (status = 200, description = "List targets", body = [TargetSummary]),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin access required"),
    ),
    tag = TAG,
)]
pub async fn list_targets(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<Json<Vec<TargetSummary>>, AppError> {
    let mut conn = state.db_pool.acquire().await?;
    let rows = targets::list(&mut conn).await?;
    Ok(Json(rows.into_iter().map(Into::into).collect()))
}

#[utoipa::path(
    patch,
    path = "/api/provisioning/targets/{id}",
    params(("id" = Uuid, Path, description = "Target id")),
    request_body = UpdateTargetInput,
    responses(
        (status = 200, description = "Updated", body = TargetSummary),
        (status = 400, description = "Invalid input"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin access required"),
        (status = 404, description = "Target not found"),
    ),
    tag = TAG,
)]
pub async fn update_target(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(id): Path<Uuid>,
    Json(input): Json<UpdateTargetInput>,
) -> Result<Json<TargetSummary>, AppError> {
    if let Some(ref n) = input.name {
        validate_name(n)?;
    }
    if let Some(ref u) = input.base_url {
        validate_base_url(u)?;
    }
    let key = targets::load_master_key()?;
    let mut conn = state.db_pool.acquire().await?;
    let updated = targets::update(
        id,
        input.name.as_deref(),
        input.base_url.as_deref(),
        input.enabled,
        input.auth_token.as_deref(),
        &key,
        &mut conn,
    )
    .await?;
    if !updated {
        return Err(AppError::NotFound);
    }
    state.provisioning_notifier.notify_one();
    let fresh = targets::get(id, &mut conn).await?.ok_or(AppError::NotFound)?;
    Ok(Json(fresh.into()))
}

#[utoipa::path(
    delete,
    path = "/api/provisioning/targets/{id}",
    params(("id" = Uuid, Path, description = "Target id")),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin access required"),
        (status = 404, description = "Target not found"),
    ),
    tag = TAG,
)]
pub async fn delete_target(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let mut conn = state.db_pool.acquire().await?;
    let deleted = targets::delete(id, &mut conn).await?;
    if !deleted {
        return Err(AppError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize, Default)]
pub struct ListJobsQuery {
    #[serde(default)]
    pub target_id: Option<Uuid>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub limit: Option<i64>,
}

#[utoipa::path(
    get,
    path = "/api/provisioning/jobs",
    params(
        ("target_id" = Option<Uuid>, Query, description = "Filter by target"),
        ("status" = Option<String>, Query, description = "Filter by status (pending|in_flight|succeeded|failed|dead)"),
        ("limit" = Option<i64>, Query, description = "Max rows (default 100, cap 500)"),
    ),
    responses(
        (status = 200, description = "Recent jobs", body = [JobSummary]),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin access required"),
    ),
    tag = TAG,
)]
pub async fn list_jobs(
    State(state): State<AppState>,
    _admin: AdminUser,
    Query(q): Query<ListJobsQuery>,
) -> Result<Json<Vec<JobSummary>>, AppError> {
    let limit = q.limit.unwrap_or(100).clamp(1, 500);
    let mut conn = state.db_pool.acquire().await?;
    let rows = jobs::list_recent(q.target_id, q.status.as_deref(), limit, &mut conn).await?;
    Ok(Json(rows.into_iter().map(Into::into).collect()))
}

#[utoipa::path(
    post,
    path = "/api/provisioning/jobs/{id}/retry",
    params(("id" = Uuid, Path, description = "Job id")),
    responses(
        (status = 204, description = "Requeued"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin access required"),
        (status = 404, description = "Job not found or not in a retryable state"),
    ),
    tag = TAG,
)]
pub async fn retry_job(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let mut conn = state.db_pool.acquire().await?;
    let did = jobs::requeue(id, &mut conn).await?;
    if !did {
        return Err(AppError::NotFound);
    }
    state.provisioning_notifier.notify_one();
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_kind_accepts_generic() {
        validate_kind(targets::KIND_GENERIC_SCIM).unwrap();
    }

    #[test]
    fn validate_kind_rejects_unknown() {
        assert!(validate_kind("slack").is_err());
    }

    #[test]
    fn validate_base_url_accepts_https() {
        validate_base_url("https://api.example.com/scim/v2").unwrap();
    }

    #[test]
    fn validate_base_url_rejects_ftp() {
        assert!(validate_base_url("ftp://api.example.com").is_err());
    }

    #[test]
    fn validate_base_url_rejects_garbage() {
        assert!(validate_base_url("not a url").is_err());
    }

    #[test]
    fn validate_name_rejects_blank_and_too_long() {
        assert!(validate_name("").is_err());
        assert!(validate_name("   ").is_err());
        assert!(validate_name(&"x".repeat(129)).is_err());
    }

    #[test]
    fn validate_name_accepts_reasonable() {
        validate_name("My Slack").unwrap();
        validate_name(&"x".repeat(128)).unwrap();
    }
}

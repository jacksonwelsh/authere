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
use crate::provisioning::{backfill, jobs, mapping, targets};

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
    /// Optional JSON object of `{"from": "to"}` strings renaming top-level SCIM body keys
    /// before dispatch (e.g. `{"externalId":"external_id"}` for snake-case peers).
    #[serde(default)]
    pub attribute_map: Option<String>,
    /// Optional URL to POST a dead-letter envelope to when a job for this target exhausts
    /// its retry budget. Intended for PagerDuty / Slack / internal alerting hooks.
    #[serde(default)]
    pub dead_letter_webhook_url: Option<String>,
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
    /// Triple-valued: field absent = leave unchanged, `null` = clear, object = set. Use the
    /// `#[serde(default, deserialize_with)]` shim below so both "missing" and explicit-null
    /// map onto the right `Option<Option<_>>` case.
    #[serde(default, deserialize_with = "de_optional_nullable_string")]
    pub attribute_map: Option<Option<String>>,
    /// Same triple-valued encoding as `attribute_map`: absent / null / url.
    #[serde(default, deserialize_with = "de_optional_nullable_string")]
    pub dead_letter_webhook_url: Option<Option<String>>,
}

fn de_optional_nullable_string<'de, D>(de: D) -> Result<Option<Option<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    // serde_json parses missing → field default = None (outer), but we want to distinguish
    // "field present but null" vs "field absent". `#[serde(default)]` already handles the
    // outer absent case via `Default`. Here we only get called when the field *is* present,
    // so we just wrap the inner Option<String> deserialization.
    use serde::Deserialize;
    let inner: Option<String> = Option::<String>::deserialize(de)?;
    Ok(Some(inner))
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
    pub backfill_done_at: Option<i64>,
    /// Attribute-rename map currently applied to this target. Canonical JSON string, or
    /// `null` if no mapping is configured.
    pub attribute_map: Option<String>,
    /// Optional alerting URL for dead-lettered jobs.
    pub dead_letter_webhook_url: Option<String>,
    /// Epoch of the last successful dispatch to this target, if any.
    pub last_success_at: Option<i64>,
    /// Epoch of the most recent `failed | dead` outcome.
    pub last_failure_at: Option<i64>,
    /// Count of consecutive failures since the last success (or all-time if never).
    pub consecutive_failures: i64,
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
            backfill_done_at: t.backfill_done_at,
            attribute_map: t.attribute_map,
            dead_letter_webhook_url: t.dead_letter_webhook_url,
            last_success_at: None,
            last_failure_at: None,
            consecutive_failures: 0,
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

fn validate_webhook_url(url: &str) -> Result<(), AppError> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        // An empty string as "present" is meaningless; reject so admins pass `null` to
        // clear.
        return Err(AppError::InputError(vec![
            "dead_letter_webhook_url must not be an empty string; pass null to clear".into(),
        ]));
    }
    let parsed = url::Url::parse(trimmed).map_err(|e| {
        AppError::InputError(vec![format!("invalid dead_letter_webhook_url: {e}")])
    })?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(AppError::InputError(vec![
            "dead_letter_webhook_url scheme must be http or https".into(),
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
    if let Some(ref m) = input.attribute_map {
        mapping::validate_map_input(m)?;
    }
    if let Some(ref url) = input.dead_letter_webhook_url {
        validate_webhook_url(url)?;
    }

    let key = targets::load_master_key()?;
    let mut tx = state.db_pool.begin().await?;
    let created = targets::create(
        input.name.trim(),
        &input.kind,
        input.base_url.trim(),
        &input.auth_token,
        input.enabled,
        Some(admin.0.user_id),
        input.attribute_map.as_deref(),
        input.dead_letter_webhook_url.as_deref(),
        &key,
        &mut tx,
    )
    .await?;
    // Kick off the initial backfill in the same transaction as the create so crash-safe:
    // if we commit the target, we commit its backfill jobs.
    let _ = backfill::run_if_needed(created.id, &state.origin, &mut tx).await?;
    tx.commit().await?;
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
    let health = jobs::compute_health(&mut conn).await?;
    let health_map: std::collections::HashMap<Uuid, jobs::TargetHealth> =
        health.into_iter().map(|h| (h.target_id, h)).collect();

    let summaries = rows
        .into_iter()
        .map(|t| {
            let mut s: TargetSummary = t.into();
            if let Some(h) = health_map.get(&s.id) {
                s.last_success_at = h.last_success_at;
                s.last_failure_at = h.last_failure_at;
                s.consecutive_failures = h.consecutive_failures;
            }
            s
        })
        .collect();
    Ok(Json(summaries))
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
    if let Some(Some(ref m)) = input.attribute_map {
        mapping::validate_map_input(m)?;
    }
    if let Some(Some(ref url)) = input.dead_letter_webhook_url {
        validate_webhook_url(url)?;
    }
    let attribute_map_arg: Option<Option<&str>> = input
        .attribute_map
        .as_ref()
        .map(|inner| inner.as_deref());
    let webhook_arg: Option<Option<&str>> = input
        .dead_letter_webhook_url
        .as_ref()
        .map(|inner| inner.as_deref());
    let key = targets::load_master_key()?;
    let mut tx = state.db_pool.begin().await?;
    let updated = targets::update(
        id,
        input.name.as_deref(),
        input.base_url.as_deref(),
        input.enabled,
        input.auth_token.as_deref(),
        attribute_map_arg,
        webhook_arg,
        &key,
        &mut tx,
    )
    .await?;
    if !updated {
        return Err(AppError::NotFound);
    }
    // If this update transitioned the target into `enabled` and it hasn't been backfilled
    // yet, run the initial sync now. `run_if_needed` no-ops otherwise so repeated PATCHes
    // that don't flip `enabled` stay cheap.
    let _ = backfill::run_if_needed(id, &state.origin, &mut tx).await?;
    let fresh = targets::get(id, &mut tx).await?.ok_or(AppError::NotFound)?;
    tx.commit().await?;
    state.provisioning_notifier.notify_one();
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

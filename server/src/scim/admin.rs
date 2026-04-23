//! Admin-facing SCIM token management. These endpoints live under `/api/scim/tokens` and use
//! the existing JWT-backed `AdminUser` extractor — they are NOT part of the `/scim/v2` surface
//! and do NOT accept SCIM bearer tokens.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::AppState;
use crate::audit::{audit, AuditContext, AuditEventType};
use crate::auth_middleware::AdminUser;
use crate::errors::AppError;
use crate::scim::token::{self, ScimTokenRecord};

const TAG: &str = "scim-admin";

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateScimTokenInput {
    /// Human-readable label, e.g. "Okta prod". Shown in the admin UI and recorded in the audit
    /// log so downstream user mutations can be attributed to a specific integration.
    pub name: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CreateScimTokenResponse {
    pub id: Uuid,
    pub name: String,
    pub created_at: i64,
    /// The plaintext bearer token. Shown exactly once; never again retrievable.
    pub token: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ScimTokenSummary {
    pub id: Uuid,
    pub name: String,
    pub created_at: i64,
    pub created_by: Uuid,
    pub last_used_at: Option<i64>,
    pub revoked_at: Option<i64>,
}

impl From<ScimTokenRecord> for ScimTokenSummary {
    fn from(r: ScimTokenRecord) -> Self {
        Self {
            id: r.id,
            name: r.name,
            created_at: r.created_at,
            created_by: r.created_by,
            last_used_at: r.last_used_at,
            revoked_at: r.revoked_at,
        }
    }
}

fn validate_name(name: &str) -> Result<(), AppError> {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed.len() > 128 {
        return Err(AppError::InputError(vec![
            "SCIM token name must be 1-128 characters".into(),
        ]));
    }
    Ok(())
}

#[utoipa::path(
    post,
    path = "/api/scim/tokens",
    request_body = CreateScimTokenInput,
    responses(
        (status = 201, description = "SCIM token created; plaintext returned once", body = CreateScimTokenResponse),
        (status = 400, description = "Invalid name"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin access required"),
    ),
    tag = TAG,
)]
pub async fn create_scim_token(
    State(state): State<AppState>,
    audit_ctx: AuditContext,
    admin: AdminUser,
    Json(input): Json<CreateScimTokenInput>,
) -> Result<(StatusCode, Json<CreateScimTokenResponse>), AppError> {
    validate_name(&input.name)?;

    let mut conn = state.db_pool.acquire().await?;
    let minted = token::mint(input.name.trim(), admin.0.user_id, &mut conn).await?;

    let _ = audit(AuditEventType::ScimTokenCreated)
        .actor(admin.0.user_id)
        .ctx(&audit_ctx)
        .details(serde_json::json!({
            "scim_token_id": minted.id,
            "scim_token_name": minted.name,
        }))
        .save(&mut conn)
        .await;

    Ok((
        StatusCode::CREATED,
        Json(CreateScimTokenResponse {
            id: minted.id,
            name: minted.name,
            created_at: minted.created_at,
            token: minted.plaintext,
        }),
    ))
}

#[utoipa::path(
    get,
    path = "/api/scim/tokens",
    responses(
        (status = 200, description = "List of SCIM tokens", body = [ScimTokenSummary]),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin access required"),
    ),
    tag = TAG,
)]
pub async fn list_scim_tokens(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<Json<Vec<ScimTokenSummary>>, AppError> {
    let mut conn = state.db_pool.acquire().await?;
    let rows = token::list(&mut conn).await?;
    Ok(Json(rows.into_iter().map(Into::into).collect()))
}

#[utoipa::path(
    delete,
    path = "/api/scim/tokens/{id}",
    params(("id" = Uuid, Path, description = "SCIM token id")),
    responses(
        (status = 204, description = "Token revoked"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin access required"),
        (status = 404, description = "Token not found"),
    ),
    tag = TAG,
)]
pub async fn revoke_scim_token(
    State(state): State<AppState>,
    audit_ctx: AuditContext,
    admin: AdminUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let mut conn = state.db_pool.acquire().await?;
    let existing = token::get(id, &mut conn).await?.ok_or(AppError::NotFound)?;
    if existing.revoked_at.is_some() {
        // Idempotent: report success even if already revoked. No need to double-log.
        return Ok(StatusCode::NO_CONTENT);
    }
    let did = token::revoke(id, &mut conn).await?;
    if did {
        let _ = audit(AuditEventType::ScimTokenRevoked)
            .actor(admin.0.user_id)
            .ctx(&audit_ctx)
            .details(serde_json::json!({
                "scim_token_id": existing.id,
                "scim_token_name": existing.name,
            }))
            .save(&mut conn)
            .await;
    }
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_name_accepts_reasonable() {
        validate_name("Okta prod").unwrap();
        validate_name("a").unwrap();
        validate_name(&"x".repeat(128)).unwrap();
    }

    #[test]
    fn validate_name_rejects_blank() {
        assert!(validate_name("").is_err());
        assert!(validate_name("   ").is_err());
    }

    #[test]
    fn validate_name_rejects_too_long() {
        assert!(validate_name(&"x".repeat(129)).is_err());
    }
}

use axum::extract::{self, Path, State};
use axum::http::StatusCode;
use serde::Deserialize;
use tracing::info;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::AppState;
use crate::audit::{audit, AuditContext, AuditEventType};
use crate::auth_middleware::AdminUser;
use crate::db::DbEntity;
use crate::errors::AppError;
use crate::role::{CreateRoleInput, Role, UserRole, ROLE_ADMIN};
use crate::user::auth::token::revoke_user_access_tokens;
use crate::user::User;

const ADMIN_TAG: &str = "admin";

/// Guard against an admin removing a role from their own account. Removing `admin` from
/// yourself would lock you out of management, and removing any other role leaves the
/// account in a non-obvious state. Assignment to yourself is still allowed — the footgun
/// is only on removal.
fn ensure_not_self_role_removal(actor_id: Uuid, target_id: Uuid) -> Result<(), AppError> {
    if actor_id == target_id {
        Err(AppError::InputError(vec![
            "You cannot remove roles from your own account. Ask another admin.".to_string(),
        ]))
    } else {
        Ok(())
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AssignRoleInput {
    pub role_id: Uuid,
}

#[utoipa::path(
    get,
    path = "/api/roles",
    responses(
        (status = 200, description = "List all roles", body = Vec<Role>),
        (status = 401, description = "Authentication required"),
        (status = 500, description = "Internal server error")
    ),
    tag = ADMIN_TAG,
)]
pub async fn list_roles(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<axum::Json<Vec<Role>>, AppError> {
    let mut conn = state.db_pool.acquire().await?;
    let roles = Role::list(&mut conn).await?;
    Ok(axum::Json(roles))
}

#[utoipa::path(
    post,
    path = "/api/roles",
    request_body(content = CreateRoleInput),
    responses(
        (status = 201, description = "Role created", body = Role),
        (status = 400, description = "Invalid input"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin access required"),
        (status = 409, description = "Role already exists"),
        (status = 500, description = "Internal server error")
    ),
    tag = ADMIN_TAG,
)]
pub async fn create_role(
    State(state): State<AppState>,
    audit_ctx: AuditContext,
    admin: AdminUser,
    extract::Json(input): extract::Json<CreateRoleInput>,
) -> Result<(StatusCode, axum::Json<Role>), AppError> {
    Role::validate_input(&input)?;

    let role = Role::new(input.name, input.description);
    let mut conn = state.db_pool.acquire().await?;
    role.save(&mut conn).await?;

    info!(role_id = %role.id, role_name = %role.name, admin = %admin.0.user_id, "role created");
    let _ = audit(AuditEventType::RoleCreated)
        .actor(admin.0.user_id)
        .ctx(&audit_ctx)
        .details(serde_json::json!({ "role_id": role.id, "role_name": role.name }))
        .save(&mut conn)
        .await;

    Ok((StatusCode::CREATED, axum::Json(role)))
}

#[utoipa::path(
    delete,
    path = "/api/roles/{id}",
    params(
        ("id" = Uuid, Path, description = "Role ID")
    ),
    responses(
        (status = 204, description = "Role deleted"),
        (status = 400, description = "Cannot delete role (in use or built-in)"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin access required"),
        (status = 404, description = "Role not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = ADMIN_TAG,
)]
pub async fn delete_role(
    State(state): State<AppState>,
    audit_ctx: AuditContext,
    admin: AdminUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let mut conn = state.db_pool.acquire().await?;

    let role_name = Role::get(id, &mut conn).await?.map(|r| r.name);
    let deleted = Role::delete(id, &mut conn).await?;
    if deleted {
        info!(role_id = %id, admin = %admin.0.user_id, "role deleted");
        let _ = audit(AuditEventType::RoleDeleted)
            .actor(admin.0.user_id)
            .ctx(&audit_ctx)
            .details(serde_json::json!({ "role_id": id, "role_name": role_name }))
            .save(&mut conn)
            .await;
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AppError::NotFound)
    }
}

// ============================================================================
// User Role Management Endpoints
// ============================================================================

#[utoipa::path(
    get,
    path = "/api/users/{user_id}/roles",
    params(
        ("user_id" = Uuid, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "List user's roles", body = Vec<UserRole>),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin access required"),
        (status = 404, description = "User not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = ADMIN_TAG,
)]
pub async fn get_user_roles(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(user_id): Path<Uuid>,
) -> Result<axum::Json<Vec<UserRole>>, AppError> {
    let mut conn = state.db_pool.acquire().await?;

    let user = User::get(user_id, &mut conn).await?;
    if user.is_none() {
        return Err(AppError::NotFound);
    }

    let roles = UserRole::get_for_user(user_id, &mut conn).await?;
    Ok(axum::Json(roles))
}

#[utoipa::path(
    post,
    path = "/api/users/{user_id}/roles",
    params(
        ("user_id" = Uuid, Path, description = "User ID")
    ),
    request_body(content = AssignRoleInput),
    responses(
        (status = 201, description = "Role assigned"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin access required"),
        (status = 404, description = "User or role not found"),
        (status = 409, description = "Role already assigned"),
        (status = 500, description = "Internal server error")
    ),
    tag = ADMIN_TAG,
)]
pub async fn assign_role(
    State(state): State<AppState>,
    audit_ctx: AuditContext,
    admin: AdminUser,
    Path(user_id): Path<Uuid>,
    extract::Json(input): extract::Json<AssignRoleInput>,
) -> Result<StatusCode, AppError> {
    let mut conn = state.db_pool.acquire().await?;

    let user = User::get(user_id, &mut conn).await?;
    if user.is_none() {
        return Err(AppError::NotFound);
    }

    let role = Role::get(input.role_id, &mut conn).await?.ok_or(AppError::NotFound)?;

    UserRole::assign(user_id, input.role_id, &mut conn).await?;
    let _ = revoke_user_access_tokens(user_id, &mut conn).await;

    info!(user_id = %user_id, role = %role.name, admin = %admin.0.user_id, "role assigned");
    let _ = audit(AuditEventType::AdminRoleAssigned)
        .user(user_id)
        .actor(admin.0.user_id)
        .ctx(&audit_ctx)
        .details(serde_json::json!({ "role_id": input.role_id, "role_name": role.name }))
        .save(&mut conn)
        .await;
    Ok(StatusCode::CREATED)
}

#[utoipa::path(
    delete,
    path = "/api/users/{user_id}/roles/{role_id}",
    params(
        ("user_id" = Uuid, Path, description = "User ID"),
        ("role_id" = Uuid, Path, description = "Role ID")
    ),
    responses(
        (status = 204, description = "Role removed"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin access required"),
        (status = 404, description = "User, role, or assignment not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = ADMIN_TAG,
)]
pub async fn remove_role(
    State(state): State<AppState>,
    audit_ctx: AuditContext,
    admin: AdminUser,
    Path((user_id, role_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    ensure_not_self_role_removal(admin.0.user_id, user_id)?;

    let mut conn = state.db_pool.acquire().await?;

    if let Some(role) = Role::get(role_id, &mut conn).await? {
        if role.name == ROLE_ADMIN {
            let admin_count: i64 = sqlx::query_scalar!(
                "SELECT COUNT(*) FROM user_roles ur INNER JOIN roles r ON r.id = ur.role_id WHERE r.name = 'admin'"
            )
            .fetch_one(&mut *conn)
            .await?;

            if admin_count <= 1 {
                return Err(AppError::InputError(vec![
                    "Cannot remove the last admin role".to_string(),
                ]));
            }
        }
    }

    let removed = UserRole::remove(user_id, role_id, &mut conn).await?;
    if removed {
        let _ = revoke_user_access_tokens(user_id, &mut conn).await;
        info!(user_id = %user_id, role_id = %role_id, admin = %admin.0.user_id, "role removed");
        let _ = audit(AuditEventType::AdminRoleRemoved)
            .user(user_id)
            .actor(admin.0.user_id)
            .ctx(&audit_ctx)
            .details(serde_json::json!({ "role_id": role_id }))
            .save(&mut conn)
            .await;
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AppError::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_role_removal_is_rejected() {
        let me = Uuid::now_v7();
        let err = ensure_not_self_role_removal(me, me).unwrap_err();
        match err {
            AppError::InputError(msgs) => {
                assert_eq!(msgs.len(), 1);
                assert!(msgs[0].contains("your own account"));
            }
            other => panic!("expected InputError, got {other:?}"),
        }
    }

    #[test]
    fn removing_from_another_user_is_allowed() {
        let me = Uuid::now_v7();
        let other = Uuid::now_v7();
        ensure_not_self_role_removal(me, other).unwrap();
    }
}

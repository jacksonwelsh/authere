use axum::extract::{self, Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use tracing::info;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::AppState;
use crate::audit::{audit, AuditContext, AuditEventType};
use crate::auth_middleware::{AdminUser, AuthUser};
use crate::db::DbEntity;
use crate::errors::AppError;
use crate::role::{Role, UserRole, ROLE_USER};
use crate::user::auth::Authenticator;
use crate::user::auth::token::{revoke_all_user_tokens};
use crate::user::{CreateUserInput, User};

const ADMIN_TAG: &str = "admin";
const AUTH_TAG: &str = "auth";

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateUserInput {
    pub name: Option<String>,
    pub email: Option<Option<String>>,
    pub username: Option<String>,
}

/// Summarize which profile fields are being touched by an update request, for
/// the audit log `details` blob. Includes the new values so the log records
/// what changed, not just that *something* changed.
fn update_user_changes(input: &UpdateUserInput) -> serde_json::Value {
    let mut changes = serde_json::Map::new();
    if let Some(ref name) = input.name {
        changes.insert("name".into(), serde_json::json!(name));
    }
    if let Some(ref email) = input.email {
        changes.insert("email".into(), serde_json::json!(email));
    }
    if let Some(ref username) = input.username {
        changes.insert("username".into(), serde_json::json!(username));
    }
    serde_json::Value::Object(changes)
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ChangePasswordInput {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AdminChangePasswordInput {
    pub new_password: String,
}

#[derive(Serialize, ToSchema)]
pub struct MeResponse {
    pub user_id: String,
    pub username: String,
    pub name: String,
    pub email: Option<String>,
    pub roles: Vec<String>,
}

#[utoipa::path(
    post,
    path = "/api/user",
    responses(
        (status = 201, description = "Created a new user"),
        (status = 400, description = "Invalid input when creating a new user"),
        (status = 409, description = "User with that username already exists"),
        (status = 500, description = "Internal error when creating the user"),
    ),
    request_body(
        content = CreateUserInput,
        example = json!(CreateUserInput {
            username: String::from("bob_burger"),
            name: String::from("Bob Belcher"),
            password: String::from("hunter2hunter2"),
            email: Some(String::from("bob@bobsburgers.net"))
        })
    ),
    tag = AUTH_TAG
)]
pub async fn create_user(
    State(state): State<AppState>,
    audit_ctx: AuditContext,
    admin: AdminUser,
    extract::Json(input): extract::Json<CreateUserInput>,
) -> Result<(StatusCode, axum::Json<User>), AppError> {
    User::validate_create_input(&input)?;

    let user = User::new(input.username, input.name, input.email);
    let authenticator = Authenticator::new_password(input.password, user.id).map_err(|e| {
        AppError::InternalError(format!(
            "Failed to create Authenticator for user {user:?} ({e})"
        ))
    })?;

    let mut tx = state.db_pool.begin().await?;
    user.save(&mut tx).await?;
    authenticator.save(&mut tx).await?;
    if let Some(user_role) = Role::get_by_name(ROLE_USER, &mut tx).await? {
        let _ = UserRole::assign(user.id, user_role.id, &mut tx).await;
    }
    tx.commit().await?;

    info!(user_id = %user.id, username = %user.username, admin = %admin.0.user_id, "admin created user");
    let mut conn = state.db_pool.acquire().await?;
    let _ = audit(AuditEventType::AdminCreateUser)
        .user(user.id)
        .actor(admin.0.user_id)
        .ctx(&audit_ctx)
        .details(serde_json::json!({ "username": user.username }))
        .save(&mut conn)
        .await;

    Ok((StatusCode::CREATED, axum::Json(user)))
}

#[utoipa::path(
    get,
    path = "/api/user",
    responses(
        (status = 200, description = "Lists all users on the system"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin access required"),
        (status = 500, description = "Internal error when listing users"),
    ),
    tag = ADMIN_TAG
)]
pub async fn get_users(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<axum::Json<Vec<User>>, AppError> {
    let mut conn = state.db_pool.acquire().await?;
    let users = User::list(&mut conn).await?;
    Ok(axum::Json(users))
}

#[utoipa::path(
    get,
    path = "/api/user/{id}",
    params(
        ("id" = Uuid, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "Retrieved a user"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin access required"),
        (status = 404, description = "User not found"),
        (status = 500, description = "Internal error when getting user"),
    ),
    tag = ADMIN_TAG
)]
pub async fn get_user(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(id): Path<Uuid>,
) -> Result<axum::Json<User>, AppError> {
    let mut conn = state.db_pool.acquire().await?;
    let user = User::get(id, &mut conn).await?;

    match user {
        Some(user) => Ok(axum::Json(user)),
        None => Err(AppError::NotFound),
    }
}

#[utoipa::path(
    patch,
    path = "/api/user/{id}",
    params(("id" = Uuid, Path, description = "User ID")),
    request_body(content = UpdateUserInput),
    responses(
        (status = 200, description = "User updated", body = User),
        (status = 400, description = "Invalid input"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin access required"),
        (status = 404, description = "User not found"),
        (status = 409, description = "Username already taken"),
    ),
    tag = ADMIN_TAG
)]
pub async fn update_user(
    State(state): State<AppState>,
    audit_ctx: AuditContext,
    admin: AdminUser,
    Path(id): Path<Uuid>,
    extract::Json(input): extract::Json<UpdateUserInput>,
) -> Result<axum::Json<User>, AppError> {
    let changes = update_user_changes(&input);

    let mut tx = state.db_pool.begin().await?;
    let mut user = User::get(id, &mut tx).await?.ok_or(AppError::NotFound)?;
    user.update(input.name, input.email, input.username, &mut tx).await?;
    tx.commit().await?;

    info!(user_id = %id, admin = %admin.0.user_id, "admin updated user");
    let mut conn = state.db_pool.acquire().await?;
    let _ = audit(AuditEventType::AdminUpdateUser)
        .user(id)
        .actor(admin.0.user_id)
        .ctx(&audit_ctx)
        .details(changes)
        .save(&mut conn)
        .await;
    Ok(axum::Json(user))
}

#[utoipa::path(
    get,
    path = "/api/me",
    responses(
        (status = 200, description = "Current user info", body = MeResponse),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "User not found"),
    ),
    tag = AUTH_TAG,
)]
pub async fn get_me(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<axum::Json<MeResponse>, AppError> {
    let mut conn = state.db_pool.acquire().await?;
    let user = User::get(auth.user_id, &mut conn).await?.ok_or(AppError::NotFound)?;
    Ok(axum::Json(MeResponse {
        user_id: auth.user_id.to_string(),
        username: user.username,
        name: user.name,
        email: user.email,
        roles: auth.roles,
    }))
}

#[utoipa::path(
    patch,
    path = "/api/me",
    request_body(content = UpdateUserInput),
    responses(
        (status = 200, description = "Profile updated", body = User),
        (status = 400, description = "Invalid input"),
        (status = 401, description = "Authentication required"),
        (status = 409, description = "Username already taken"),
    ),
    tag = AUTH_TAG
)]
pub async fn update_me(
    State(state): State<AppState>,
    audit_ctx: AuditContext,
    auth: AuthUser,
    extract::Json(input): extract::Json<UpdateUserInput>,
) -> Result<axum::Json<User>, AppError> {
    let changes = update_user_changes(&input);

    let mut tx = state.db_pool.begin().await?;
    let mut user = User::get(auth.user_id, &mut tx).await?.ok_or(AppError::NotFound)?;
    user.update(input.name, input.email, input.username, &mut tx).await?;
    tx.commit().await?;

    let mut conn = state.db_pool.acquire().await?;
    let _ = audit(AuditEventType::UserUpdated)
        .user(auth.user_id)
        .ctx(&audit_ctx)
        .details(changes)
        .save(&mut conn)
        .await;
    Ok(axum::Json(user))
}

#[utoipa::path(
    patch,
    path = "/api/me/password",
    request_body(content = ChangePasswordInput),
    responses(
        (status = 204, description = "Password changed, all sessions revoked"),
        (status = 400, description = "New password does not meet requirements"),
        (status = 401, description = "Authentication required or current password incorrect"),
        (status = 404, description = "User not found"),
    ),
    tag = AUTH_TAG
)]
pub async fn change_my_password(
    State(state): State<AppState>,
    audit_ctx: AuditContext,
    auth: AuthUser,
    extract::Json(input): extract::Json<ChangePasswordInput>,
) -> Result<StatusCode, AppError> {
    Authenticator::validate_password(&input.new_password)
        .map_err(|e| AppError::InputError(vec![e]))?;

    let mut conn = state.db_pool.acquire().await?;
    let user = User::get(auth.user_id, &mut conn).await?.ok_or(AppError::NotFound)?;

    Authenticator::try_password_login(&user, input.current_password, &mut conn).await?;
    Authenticator::update_password(auth.user_id, input.new_password, &mut conn).await?;
    revoke_all_user_tokens(auth.user_id, &mut conn).await?;

    info!(user_id = %auth.user_id, "user changed their password");
    let _ = audit(AuditEventType::PasswordChanged)
        .user(auth.user_id)
        .ctx(&audit_ctx)
        .save(&mut conn)
        .await;

    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    put,
    path = "/api/user/{id}/password",
    params(("id" = Uuid, Path, description = "User ID")),
    request_body(content = AdminChangePasswordInput),
    responses(
        (status = 204, description = "Password changed, all user sessions revoked"),
        (status = 400, description = "New password does not meet requirements"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin access required"),
        (status = 404, description = "User not found"),
    ),
    tag = ADMIN_TAG
)]
pub async fn admin_change_user_password(
    State(state): State<AppState>,
    audit_ctx: AuditContext,
    admin: AdminUser,
    Path(id): Path<Uuid>,
    extract::Json(input): extract::Json<AdminChangePasswordInput>,
) -> Result<StatusCode, AppError> {
    Authenticator::validate_password(&input.new_password)
        .map_err(|e| AppError::InputError(vec![e]))?;

    let mut conn = state.db_pool.acquire().await?;
    User::get(id, &mut conn).await?.ok_or(AppError::NotFound)?;

    Authenticator::update_password(id, input.new_password, &mut conn).await?;
    revoke_all_user_tokens(id, &mut conn).await?;

    info!(user_id = %id, admin = %admin.0.user_id, "admin reset user password");
    let _ = audit(AuditEventType::AdminPasswordReset)
        .user(id)
        .actor(admin.0.user_id)
        .ctx(&audit_ctx)
        .save(&mut conn)
        .await;

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn me_response_serializes_profile_fields() {
        let resp = MeResponse {
            user_id: "00000000-0000-0000-0000-000000000001".into(),
            username: "alice".into(),
            name: "Alice Example".into(),
            email: Some("alice@example.com".into()),
            roles: vec!["user".into(), "admin".into()],
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["user_id"], "00000000-0000-0000-0000-000000000001");
        assert_eq!(json["username"], "alice");
        assert_eq!(json["name"], "Alice Example");
        assert_eq!(json["email"], "alice@example.com");
        assert_eq!(json["roles"], serde_json::json!(["user", "admin"]));
    }

    #[test]
    fn me_response_serializes_null_email() {
        let resp = MeResponse {
            user_id: "00000000-0000-0000-0000-000000000002".into(),
            username: "bob".into(),
            name: "Bob".into(),
            email: None,
            roles: vec![],
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json["email"].is_null());
        assert_eq!(json["roles"], serde_json::json!([]));
    }
}

use std::env;
use std::net::SocketAddr;
use std::time::Duration;

use crate::application::{Application, CreateApplicationInput, UpdateApplicationInput};
use crate::audit::{list_audit_log, log_admin_role_assigned, log_admin_role_removed, log_admin_update_user, log_invitation_consumed, log_invitation_created, log_invitation_deleted, log_login_failed, log_login_success, log_logout, log_password_changed, log_settings_updated, log_token_refresh, log_user_created, log_user_registered, AuditLogRecord};
use crate::auth_middleware::{AdminUser, AuthUser};
use crate::cli::{Cli, Commands};
use crate::db::DbEntity;
use crate::errors::AppError;
use crate::invitation::{CreateInvitationInput, Invitation, InvitationWithStatus};
use crate::rate_limit::{RateLimitConfig, RateLimitExceeded, RateLimiter};
use crate::role::{CreateRoleInput, Role, UserRole};
use crate::settings::{SettingsResponse, UpdateSettingsInput, open_registration_enabled, set_setting};
use crate::user::auth::token::{self, TokenPair, generate_token_pair, verify_access_token, verify_and_revoke_refresh_token, revoke_user_access_tokens, revoke_all_user_tokens};
use crate::user::auth::Authenticator;
use crate::user::{CreateUserInput, LoginInput, User};

use axum::extract::{self, ConnectInfo, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum_extra::TypedHeader;
use clap::Parser;
use headers::UserAgent;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use utoipa::{OpenApi, ToSchema};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use utoipa_swagger_ui::SwaggerUi;
use uuid::Uuid;

const ADMIN_TAG: &str = "admin";
const AUTH_TAG: &str = "auth";

pub mod application;
pub mod audit;
pub mod auth_middleware;
pub mod cli;
pub mod db;
pub mod errors;
pub mod invitation;
pub mod rate_limit;
pub mod role;
pub mod settings;
pub mod static_files;
pub mod user;

#[derive(OpenApi)]
#[openapi(
    tags(
        (name = ADMIN_TAG, description = "Admin API endpoints"),
        (name = AUTH_TAG, description = "Authentication API endpoints")
    )
)]
struct ApiDoc;

#[derive(Clone)]
struct AppState {
    db_pool: SqlitePool,
    login_rate_limiter: RateLimiter,
    register_rate_limiter: RateLimiter,
}

impl axum::extract::FromRef<AppState> for SqlitePool {
    fn from_ref(state: &AppState) -> Self {
        state.db_pool.clone()
    }
}

/// Error type that can be either an AppError or a RateLimitExceeded
pub enum LoginError {
    App(AppError),
    RateLimit(RateLimitExceeded),
}

impl IntoResponse for LoginError {
    fn into_response(self) -> Response {
        match self {
            LoginError::App(e) => e.into_response(),
            LoginError::RateLimit(e) => e.into_response(),
        }
    }
}

impl From<AppError> for LoginError {
    fn from(e: AppError) -> Self {
        LoginError::App(e)
    }
}

impl From<sqlx::Error> for LoginError {
    fn from(e: sqlx::Error) -> Self {
        LoginError::App(AppError::from(e))
    }
}

pub enum RegisterError {
    App(AppError),
    RateLimit(RateLimitExceeded),
}

impl IntoResponse for RegisterError {
    fn into_response(self) -> Response {
        match self {
            RegisterError::App(e) => e.into_response(),
            RegisterError::RateLimit(e) => e.into_response(),
        }
    }
}

impl From<AppError> for RegisterError {
    fn from(e: AppError) -> Self {
        RegisterError::App(e)
    }
}

impl From<sqlx::Error> for RegisterError {
    fn from(e: sqlx::Error) -> Self {
        RegisterError::App(AppError::from(e))
    }
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    dotenvy::dotenv().ok(); // load .env from working directory if present

    let cli = Cli::parse();

    let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| {
        eprintln!("DATABASE_URL not set, using default: sqlite:./data.db");
        String::from("sqlite:./data.db")
    });
    let db_pool = SqlitePool::connect(&database_url)
        .await
        .expect("Could not connect to sqlite!");

    let mut conn = db_pool.acquire().await?;
    token::try_initialize(&mut conn).await?;
    drop(conn);

    // Handle CLI commands
    match cli.command {
        Some(Commands::InitAdmin {
            username,
            password,
            name,
            email,
        }) => {
            let password = match password {
                Some(p) => p,
                None => cli::prompt_password().map_err(|e| {
                    AppError::InternalError(format!("Failed to read password: {e}"))
                })?,
            };
            cli::init_admin(&db_pool, username, password, name, email).await?;
            return Ok(());
        }
        Some(Commands::Serve) | None => {
            // Continue to serve
        }
    }

    // Configure rate limiter: 5 login attempts per minute per IP
    let login_rate_limiter = RateLimiter::new(RateLimitConfig {
        max_requests: 5,
        window: Duration::from_secs(60),
    });

    // 3 registration attempts per hour per IP
    let register_rate_limiter = RateLimiter::new(RateLimitConfig {
        max_requests: 3,
        window: Duration::from_secs(3600),
    });

    let state = AppState {
        db_pool,
        login_rate_limiter,
        register_rate_limiter,
    };

    let (router, api) = OpenApiRouter::with_openapi(ApiDoc::openapi())
        .routes(routes!(create_user, get_users))
        .routes(routes!(get_user, update_user))
        .routes(routes!(login))
        .routes(routes!(refresh_token))
        .routes(routes!(logout))
        // Registration
        .routes(routes!(register))
        .routes(routes!(validate_invite))
        // Role management
        .routes(routes!(list_roles))
        .routes(routes!(create_role))
        .routes(routes!(delete_role))
        // User role management
        .routes(routes!(get_user_roles))
        .routes(routes!(assign_role))
        .routes(routes!(remove_role))
        // Application management
        .routes(routes!(list_applications))
        .routes(routes!(create_application))
        .routes(routes!(get_application))
        .routes(routes!(update_application))
        .routes(routes!(delete_application))
        // Forward auth
        .routes(routes!(verify_auth))
        // Browser-friendly auth
        .routes(routes!(browser_login))
        .routes(routes!(browser_logout))
        .routes(routes!(browser_refresh))
        // Admin UI API
        .routes(routes!(get_me, update_me))
        .routes(routes!(change_my_password))
        .routes(routes!(admin_change_user_password))
        .routes(routes!(get_audit_log))
        // Admin settings
        .routes(routes!(get_settings, update_settings))
        // Admin invitations
        .routes(routes!(list_invitations, create_invitation))
        .routes(routes!(delete_invitation))
        .with_state(state)
        .split_for_parts();

    let router = router
        .merge(SwaggerUi::new("/docs").url("/apidoc/openapi.json", api))
        // Static assets (hashed filenames — long cache)
        .route("/assets/{*path}", axum::routing::get(static_files::serve_asset))
        // SPA shell — served for all UI routes
        .route("/", axum::routing::get(static_files::serve_spa))
        .route("/login", axum::routing::get(static_files::serve_spa))
        .route("/admin", axum::routing::get(static_files::serve_spa))
        .route("/admin/{*path}", axum::routing::get(static_files::serve_spa))
        .route("/account", axum::routing::get(static_files::serve_spa))
        .route("/credentials", axum::routing::get(static_files::serve_spa))
        .route("/register", axum::routing::get(static_files::serve_spa));

    println!("Starting server on 0.0.0.0:3000");
    println!("Swagger UI available at http://localhost:3000/docs");

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    Ok(axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()).await?)
}

#[utoipa::path(
    post,
    path = "/user",
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
async fn create_user(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    admin: AdminUser,
    extract::Json(input): extract::Json<CreateUserInput>,
) -> Result<(StatusCode, axum::Json<User>), AppError> {
    let ip_str = addr.ip().to_string();
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
    if let Some(user_role) = Role::get_by_name("user", &mut tx).await? {
        let _ = UserRole::assign(user.id, user_role.id, &mut tx).await;
    }
    tx.commit().await?;

    let mut conn = state.db_pool.acquire().await?;
    let _ = log_user_created(user.id, Some(admin.0.user_id), &ip_str, &mut conn).await;

    Ok((StatusCode::CREATED, axum::Json(user)))
}

#[utoipa::path(
    get,
    path = "/user",
    responses(
        (status = 200, description = "Lists all users on the system"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin access required"),
        (status = 500, description = "Internal error when listing users"),
    ),
    tag = ADMIN_TAG
)]
async fn get_users(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<axum::Json<Vec<User>>, AppError> {
    let mut conn = state.db_pool.acquire().await?;
    let users = User::list(&mut conn).await?;

    Ok(axum::Json(users))
}

#[utoipa::path(
    get,
    path = "/user/{id}",
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
async fn get_user(
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

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateUserInput {
    pub name: Option<String>,
    pub email: Option<Option<String>>,
    pub username: Option<String>,
}

#[utoipa::path(
    patch,
    path = "/user/{id}",
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
async fn update_user(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    admin: AdminUser,
    Path(id): Path<Uuid>,
    extract::Json(input): extract::Json<UpdateUserInput>,
) -> Result<axum::Json<User>, AppError> {
    let ip_str = addr.ip().to_string();
    let mut conn = state.db_pool.acquire().await?;
    let mut user = User::get(id, &mut conn).await?.ok_or(AppError::NotFound)?;
    user.update(input.name, input.email, input.username, &mut conn).await?;
    let _ = log_admin_update_user(id, admin.0.user_id, &ip_str, &mut conn).await;
    Ok(axum::Json(user))
}

#[utoipa::path(
    patch,
    path = "/me",
    request_body(content = UpdateUserInput),
    responses(
        (status = 200, description = "Profile updated", body = User),
        (status = 400, description = "Invalid input"),
        (status = 401, description = "Authentication required"),
        (status = 409, description = "Username already taken"),
    ),
    tag = AUTH_TAG
)]
async fn update_me(
    State(state): State<AppState>,
    auth: AuthUser,
    extract::Json(input): extract::Json<UpdateUserInput>,
) -> Result<axum::Json<User>, AppError> {
    let mut conn = state.db_pool.acquire().await?;
    let mut user = User::get(auth.user_id, &mut conn).await?.ok_or(AppError::NotFound)?;
    user.update(input.name, input.email, input.username, &mut conn).await?;
    Ok(axum::Json(user))
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

#[utoipa::path(
    patch,
    path = "/me/password",
    request_body(content = ChangePasswordInput),
    responses(
        (status = 204, description = "Password changed, all sessions revoked"),
        (status = 400, description = "New password does not meet requirements"),
        (status = 401, description = "Authentication required or current password incorrect"),
        (status = 404, description = "User not found"),
    ),
    tag = AUTH_TAG
)]
async fn change_my_password(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    auth: AuthUser,
    extract::Json(input): extract::Json<ChangePasswordInput>,
) -> Result<StatusCode, AppError> {
    let ip_str = addr.ip().to_string();

    Authenticator::validate_password(&input.new_password)
        .map_err(|e| AppError::InputError(vec![e]))?;

    let mut conn = state.db_pool.acquire().await?;
    let user = User::get(auth.user_id, &mut conn).await?.ok_or(AppError::NotFound)?;

    Authenticator::try_password_login(&user, input.current_password, &mut conn).await?;
    Authenticator::update_password(auth.user_id, input.new_password, &mut conn).await?;
    revoke_all_user_tokens(auth.user_id, &mut conn).await?;
    let _ = log_password_changed(auth.user_id, None, &ip_str, &mut conn).await;

    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    put,
    path = "/user/{id}/password",
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
async fn admin_change_user_password(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    admin: AdminUser,
    Path(id): Path<Uuid>,
    extract::Json(input): extract::Json<AdminChangePasswordInput>,
) -> Result<StatusCode, AppError> {
    let ip_str = addr.ip().to_string();

    Authenticator::validate_password(&input.new_password)
        .map_err(|e| AppError::InputError(vec![e]))?;

    let mut conn = state.db_pool.acquire().await?;
    User::get(id, &mut conn).await?.ok_or(AppError::NotFound)?;

    Authenticator::update_password(id, input.new_password, &mut conn).await?;
    revoke_all_user_tokens(id, &mut conn).await?;
    let _ = log_password_changed(id, Some(admin.0.user_id), &ip_str, &mut conn).await;

    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/login",
    request_body(
        content = LoginInput,
        example = json!(LoginInput {
            username: String::from("bob_burger"),
            password: String::from("hunter2hunter2"),
        }),
    ),
    responses(
        (status = 200, description = "Successful login", body = TokenPair),
        (status = 400, description = "Invalid username or password"),
        (status = 401, description = "Incorrect username or password"),
        (status = 429, description = "Too many login attempts"),
        (status = 500, description = "Internal server error")
    ),
    tag = AUTH_TAG,
)]
async fn login(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    user_agent: Option<TypedHeader<UserAgent>>,
    extract::Json(input): extract::Json<LoginInput>,
) -> Result<axum::Json<TokenPair>, LoginError> {
    let client_ip = addr.ip();
    let ip_str = client_ip.to_string();
    let ua_str = user_agent.map(|h| h.to_string());

    // Check rate limit before processing
    if let Err(retry_after) = state.login_rate_limiter.check(client_ip).await {
        return Err(LoginError::RateLimit(RateLimitExceeded { retry_after }));
    }

    let mut conn = state.db_pool.acquire().await?;
    // Be kind to users, throw a different error if password doesn't meet requirements
    if let Err(msg) = Authenticator::validate_password(&input.password) {
        return Err(AppError::InputError(vec![msg]).into());
    }

    let username = input.username.clone();
    let user = match User::login(input, &mut conn).await {
        Ok(user) => user,
        Err(e) => {
            state.login_rate_limiter.record_failure(client_ip).await;
            let failed_user_id = User::get_by_username(&username, &mut conn).await.ok().flatten().map(|u| u.id);
            let _ = log_login_failed(&username, failed_user_id, &ip_str, ua_str, &mut conn).await;
            return Err(e.into());
        }
    };

    let roles = user.get_roles(&mut conn).await?;
    let token_pair = generate_token_pair(user.id, roles, &mut conn).await?;

    // Log successful login
    let _ = log_login_success(user.id, &ip_str, ua_str, &mut conn).await;

    Ok(axum::Json(token_pair))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RefreshTokenInput {
    pub refresh_token: String,
}

/// Cookie configuration
const AUTH_COOKIE_NAME: &str = "authere_token";
const REFRESH_COOKIE_NAME: &str = "authere_refresh";

/// Build Set-Cookie header for authentication
fn build_auth_cookie(token: &str, max_age_secs: i64) -> String {
    format!(
        "{}={}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={}",
        AUTH_COOKIE_NAME, token, max_age_secs
    )
}

/// Build Set-Cookie header for refresh token
fn build_refresh_cookie(token: &str, max_age_secs: i64) -> String {
    format!(
        "{}={}; HttpOnly; Secure; SameSite=Lax; Path=/auth; Max-Age={}",
        REFRESH_COOKIE_NAME, token, max_age_secs
    )
}

/// Clear authentication cookies
fn clear_auth_cookies() -> Vec<String> {
    vec![
        format!("{}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0", AUTH_COOKIE_NAME),
        format!("{}=; HttpOnly; Secure; SameSite=Lax; Path=/auth; Max-Age=0", REFRESH_COOKIE_NAME),
    ]
}

#[utoipa::path(
    post,
    path = "/auth/refresh",
    request_body(content = RefreshTokenInput),
    responses(
        (status = 200, description = "Token refreshed", body = TokenPair),
        (status = 401, description = "Invalid or expired refresh token"),
        (status = 500, description = "Internal server error")
    ),
    tag = AUTH_TAG,
)]
async fn refresh_token(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    extract::Json(input): extract::Json<RefreshTokenInput>,
) -> Result<axum::Json<TokenPair>, AppError> {
    let ip_str = addr.ip().to_string();
    let mut conn = state.db_pool.acquire().await?;

    // Atomically verify and revoke the refresh token (prevents replay via race condition)
    let user_id = verify_and_revoke_refresh_token(&input.refresh_token, &mut conn).await?;

    // Get user and their roles
    let user = User::get(user_id, &mut conn)
        .await?
        .ok_or(AppError::AuthenticationRequired)?;
    let roles = user.get_roles(&mut conn).await?;

    // Generate new token pair
    let token_pair = generate_token_pair(user_id, roles, &mut conn).await?;

    // Log the token refresh
    let _ = log_token_refresh(user_id, &ip_str, &mut conn).await;

    Ok(axum::Json(token_pair))
}

#[utoipa::path(
    post,
    path = "/auth/logout",
    request_body(content = RefreshTokenInput),
    responses(
        (status = 204, description = "Logged out successfully"),
        (status = 401, description = "Invalid refresh token"),
        (status = 500, description = "Internal server error")
    ),
    tag = AUTH_TAG,
)]
async fn logout(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    extract::Json(input): extract::Json<RefreshTokenInput>,
) -> Result<StatusCode, AppError> {
    let ip_str = addr.ip().to_string();
    let mut conn = state.db_pool.acquire().await?;

    // Atomically verify and revoke the refresh token
    let user_id = verify_and_revoke_refresh_token(&input.refresh_token, &mut conn).await?;

    // Revoke all in-flight access tokens for this user
    let _ = revoke_user_access_tokens(user_id, &mut conn).await;

    // Log the logout
    let _ = log_logout(user_id, &ip_str, &mut conn).await;

    Ok(StatusCode::NO_CONTENT)
}

// ============================================================================
// Role Management Endpoints
// ============================================================================

#[utoipa::path(
    get,
    path = "/roles",
    responses(
        (status = 200, description = "List all roles", body = Vec<Role>),
        (status = 401, description = "Authentication required"),
        (status = 500, description = "Internal server error")
    ),
    tag = ADMIN_TAG,
)]
async fn list_roles(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<axum::Json<Vec<Role>>, AppError> {
    let mut conn = state.db_pool.acquire().await?;
    let roles = Role::list(&mut conn).await?;
    Ok(axum::Json(roles))
}

#[utoipa::path(
    post,
    path = "/roles",
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
async fn create_role(
    State(state): State<AppState>,
    _admin: AdminUser,
    extract::Json(input): extract::Json<CreateRoleInput>,
) -> Result<(StatusCode, axum::Json<Role>), AppError> {
    Role::validate_input(&input)?;

    let role = Role::new(input.name, input.description);
    let mut conn = state.db_pool.acquire().await?;
    role.save(&mut conn).await?;

    Ok((StatusCode::CREATED, axum::Json(role)))
}

#[utoipa::path(
    delete,
    path = "/roles/{id}",
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
async fn delete_role(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let mut conn = state.db_pool.acquire().await?;

    let deleted = Role::delete(id, &mut conn).await?;
    if deleted {
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
    path = "/users/{user_id}/roles",
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
async fn get_user_roles(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(user_id): Path<Uuid>,
) -> Result<axum::Json<Vec<UserRole>>, AppError> {
    let mut conn = state.db_pool.acquire().await?;

    // Check user exists
    let user = User::get(user_id, &mut conn).await?;
    if user.is_none() {
        return Err(AppError::NotFound);
    }

    let roles = UserRole::get_for_user(user_id, &mut conn).await?;
    Ok(axum::Json(roles))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AssignRoleInput {
    pub role_id: Uuid,
}

#[utoipa::path(
    post,
    path = "/users/{user_id}/roles",
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
async fn assign_role(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    admin: AdminUser,
    Path(user_id): Path<Uuid>,
    extract::Json(input): extract::Json<AssignRoleInput>,
) -> Result<StatusCode, AppError> {
    let ip_str = addr.ip().to_string();
    let mut conn = state.db_pool.acquire().await?;

    // Check user exists
    let user = User::get(user_id, &mut conn).await?;
    if user.is_none() {
        return Err(AppError::NotFound);
    }

    // Check role exists
    let role = Role::get(input.role_id, &mut conn).await?.ok_or(AppError::NotFound)?;

    UserRole::assign(user_id, input.role_id, &mut conn).await?;
    let _ = log_admin_role_assigned(user_id, admin.0.user_id, input.role_id, &role.name, &ip_str, &mut conn).await;
    Ok(StatusCode::CREATED)
}

#[utoipa::path(
    delete,
    path = "/users/{user_id}/roles/{role_id}",
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
async fn remove_role(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    admin: AdminUser,
    Path((user_id, role_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    let ip_str = addr.ip().to_string();
    let mut conn = state.db_pool.acquire().await?;

    let removed = UserRole::remove(user_id, role_id, &mut conn).await?;
    if removed {
        let _ = log_admin_role_removed(user_id, admin.0.user_id, role_id, &ip_str, &mut conn).await;
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AppError::NotFound)
    }
}

// ============================================================================
// Application Management Endpoints
// ============================================================================

#[utoipa::path(
    get,
    path = "/applications",
    responses(
        (status = 200, description = "List all applications", body = Vec<Application>),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin access required"),
        (status = 500, description = "Internal server error")
    ),
    tag = ADMIN_TAG,
)]
async fn list_applications(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<axum::Json<Vec<Application>>, AppError> {
    let mut conn = state.db_pool.acquire().await?;
    let apps = Application::list(&mut conn).await?;
    Ok(axum::Json(apps))
}

#[utoipa::path(
    post,
    path = "/applications",
    request_body(content = CreateApplicationInput),
    responses(
        (status = 201, description = "Application created", body = Application),
        (status = 400, description = "Invalid input"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin access required"),
        (status = 409, description = "Application with that slug already exists"),
        (status = 500, description = "Internal server error")
    ),
    tag = ADMIN_TAG,
)]
async fn create_application(
    State(state): State<AppState>,
    _admin: AdminUser,
    extract::Json(input): extract::Json<CreateApplicationInput>,
) -> Result<(StatusCode, axum::Json<Application>), AppError> {
    Application::validate_input(&input)?;

    let app = Application::new(input);
    let mut conn = state.db_pool.acquire().await?;
    app.save(&mut conn).await?;

    Ok((StatusCode::CREATED, axum::Json(app)))
}

#[utoipa::path(
    get,
    path = "/applications/{id}",
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
async fn get_application(
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
    path = "/applications/{id}",
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
async fn update_application(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(id): Path<Uuid>,
    extract::Json(input): extract::Json<UpdateApplicationInput>,
) -> Result<axum::Json<Application>, AppError> {
    let mut conn = state.db_pool.acquire().await?;
    let mut app = Application::get(id, &mut conn)
        .await?
        .ok_or(AppError::NotFound)?;

    app.update(input, &mut conn).await?;
    Ok(axum::Json(app))
}

#[utoipa::path(
    delete,
    path = "/applications/{id}",
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
async fn delete_application(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let mut conn = state.db_pool.acquire().await?;

    let deleted = Application::delete(id, &mut conn).await?;
    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AppError::NotFound)
    }
}

// ============================================================================
// Forward Auth Endpoint
// ============================================================================

use axum::http::header::{HeaderMap, HeaderName, HeaderValue};

/// Response headers for successful forward auth
fn build_auth_headers(user: &User, roles: &[String], email: Option<&str>) -> HeaderMap {
    let mut headers = HeaderMap::new();

    headers.insert(
        HeaderName::from_static("x-auth-user"),
        HeaderValue::from_str(&user.id.to_string()).unwrap_or_else(|_| HeaderValue::from_static("")),
    );

    headers.insert(
        HeaderName::from_static("x-auth-username"),
        HeaderValue::from_str(&user.username).unwrap_or_else(|_| HeaderValue::from_static("")),
    );

    headers.insert(
        HeaderName::from_static("x-auth-roles"),
        HeaderValue::from_str(&roles.join(",")).unwrap_or_else(|_| HeaderValue::from_static("")),
    );

    if let Some(email) = email {
        if let Ok(value) = HeaderValue::from_str(email) {
            headers.insert(HeaderName::from_static("x-auth-email"), value);
        }
    }

    headers
}

#[utoipa::path(
    get,
    path = "/auth/verify",
    responses(
        (status = 200, description = "Authenticated and authorized"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized for this application"),
        (status = 500, description = "Internal server error")
    ),
    tag = AUTH_TAG,
)]
async fn verify_auth(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<(StatusCode, HeaderMap), AppError> {
    let mut conn = state.db_pool.acquire().await?;

    // Extract the Authorization header
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok());

    // Also check for cookie-based auth (for browser requests)
    let cookie_token = headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies
                .split(';')
                .map(|s| s.trim())
                .find(|s| s.starts_with("authere_token="))
                .map(|s| s.strip_prefix("authere_token=").unwrap_or(""))
        });

    // Get the token from either source
    let token = auth_header
        .and_then(|h| h.strip_prefix("Bearer "))
        .or(cookie_token)
        .ok_or(AppError::AuthenticationRequired)?;

    // Verify the token
    let claims = verify_access_token(token, &mut conn).await?;

    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::InternalError("Invalid user ID in token".to_string()))?;

    // Get user details
    let user = User::get(user_id, &mut conn)
        .await?
        .ok_or(AppError::AuthenticationRequired)?;

    // Check if there's an application that matches the request
    let host = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get("host"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let path = headers
        .get("x-forwarded-uri")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("/");

    // Find matching application
    if let Some(app) = Application::find_matching(host, path, &mut conn).await? {
        // Check if user has required roles
        if !app.check_access(&claims.roles) {
            return Err(AppError::Forbidden);
        }
    }
    // If no application matches, allow access (just authentication required)

    // Build response headers
    let response_headers = build_auth_headers(&user, &claims.roles, user.email.as_deref());

    Ok((StatusCode::OK, response_headers))
}

// ============================================================================
// Browser-Friendly Auth Endpoints
// ============================================================================

#[derive(Debug, Deserialize, ToSchema)]
pub struct BrowserLoginQuery {
    /// URL to redirect to after successful login
    pub redirect_uri: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BrowserLoginResponse {
    pub success: bool,
    pub redirect_uri: Option<String>,
}

/// Browser-friendly login that sets cookies and optionally redirects
#[utoipa::path(
    post,
    path = "/auth/login",
    request_body(content = LoginInput),
    params(
        ("redirect_uri" = Option<String>, Query, description = "URL to redirect to after login")
    ),
    responses(
        (status = 200, description = "Login successful, cookies set"),
        (status = 302, description = "Login successful, redirecting"),
        (status = 400, description = "Invalid input"),
        (status = 401, description = "Invalid credentials"),
        (status = 429, description = "Too many login attempts"),
        (status = 500, description = "Internal server error")
    ),
    tag = AUTH_TAG,
)]
async fn browser_login(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    user_agent: Option<TypedHeader<UserAgent>>,
    Query(query): Query<BrowserLoginQuery>,
    extract::Json(input): extract::Json<LoginInput>,
) -> Result<Response, LoginError> {
    let client_ip = addr.ip();
    let ip_str = client_ip.to_string();
    let ua_str = user_agent.map(|h| h.to_string());

    // Check rate limit
    if let Err(retry_after) = state.login_rate_limiter.check(client_ip).await {
        return Err(LoginError::RateLimit(RateLimitExceeded { retry_after }));
    }

    let mut conn = state.db_pool.acquire().await?;

    if let Err(msg) = Authenticator::validate_password(&input.password) {
        return Err(AppError::InputError(vec![msg]).into());
    }

    let username = input.username.clone();
    let user = match User::login(input, &mut conn).await {
        Ok(user) => user,
        Err(e) => {
            state.login_rate_limiter.record_failure(client_ip).await;
            let failed_user_id = User::get_by_username(&username, &mut conn).await.ok().flatten().map(|u| u.id);
            let _ = log_login_failed(&username, failed_user_id, &ip_str, ua_str, &mut conn).await;
            return Err(e.into());
        }
    };

    let roles = user.get_roles(&mut conn).await?;
    let token_pair = generate_token_pair(user.id, roles, &mut conn).await?;

    let _ = log_login_success(user.id, &ip_str, ua_str, &mut conn).await;

    // Build response with cookies
    let access_cookie = build_auth_cookie(&token_pair.access_token, token_pair.expires_in);
    let refresh_cookie = build_refresh_cookie(
        &token_pair.refresh_token,
        crate::user::auth::token::REFRESH_TOKEN_LIFETIME,
    );

    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::SET_COOKIE,
        access_cookie.parse().unwrap(),
    );
    headers.append(
        axum::http::header::SET_COOKIE,
        refresh_cookie.parse().unwrap(),
    );

    // If redirect_uri is provided, redirect there
    if let Some(redirect_uri) = query.redirect_uri {
        // Validate redirect URI (only allow relative paths or same-origin for security)
        if redirect_uri.starts_with('/') {
            headers.insert(
                axum::http::header::LOCATION,
                redirect_uri.parse().unwrap(),
            );
            return Ok((StatusCode::SEE_OTHER, headers).into_response());
        }
    }

    // Return JSON response with cookies
    Ok((
        StatusCode::OK,
        headers,
        axum::Json(BrowserLoginResponse {
            success: true,
            redirect_uri: None,
        }),
    )
        .into_response())
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct BrowserLogoutQuery {
    /// URL to redirect to after logout
    pub redirect_uri: Option<String>,
}

/// Browser-friendly logout that clears cookies
#[utoipa::path(
    post,
    path = "/auth/browser-logout",
    params(
        ("redirect_uri" = Option<String>, Query, description = "URL to redirect to after logout")
    ),
    responses(
        (status = 200, description = "Logged out, cookies cleared"),
        (status = 302, description = "Logged out, redirecting"),
        (status = 500, description = "Internal server error")
    ),
    tag = AUTH_TAG,
)]
async fn browser_logout(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<BrowserLogoutQuery>,
) -> Result<Response, AppError> {
    let ip_str = addr.ip().to_string();
    let mut conn = state.db_pool.acquire().await?;

    // Try to get the refresh token from cookies to revoke it
    let refresh_token = headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies
                .split(';')
                .map(|s| s.trim())
                .find(|s| s.starts_with("authere_refresh="))
                .map(|s| s.strip_prefix("authere_refresh=").unwrap_or(""))
        });

    // If we have a refresh token, try to revoke it and log the logout
    if let Some(token) = refresh_token {
        if let Ok(user_id) = verify_and_revoke_refresh_token(token, &mut conn).await {
            let _ = revoke_user_access_tokens(user_id, &mut conn).await;
            let _ = log_logout(user_id, &ip_str, &mut conn).await;
        }
    }

    // Clear cookies
    let clear_cookies = clear_auth_cookies();

    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::SET_COOKIE,
        clear_cookies[0].parse().unwrap(),
    );
    headers.append(
        axum::http::header::SET_COOKIE,
        clear_cookies[1].parse().unwrap(),
    );

    // If redirect_uri is provided, redirect there
    if let Some(redirect_uri) = query.redirect_uri {
        if redirect_uri.starts_with('/') {
            headers.insert(
                axum::http::header::LOCATION,
                redirect_uri.parse().unwrap(),
            );
            return Ok((StatusCode::SEE_OTHER, headers).into_response());
        }
    }

    Ok((
        StatusCode::OK,
        headers,
        axum::Json(serde_json::json!({ "success": true })),
    )
        .into_response())
}

/// Browser-friendly token refresh that reads the refresh token from a cookie
#[utoipa::path(
    post,
    path = "/auth/browser-refresh",
    responses(
        (status = 200, description = "Token refreshed, new cookies set"),
        (status = 401, description = "Missing or invalid refresh token"),
        (status = 500, description = "Internal server error")
    ),
    tag = AUTH_TAG,
)]
async fn browser_refresh(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let ip_str = addr.ip().to_string();
    let mut conn = state.db_pool.acquire().await?;

    let refresh_token_str = headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies
                .split(';')
                .map(|s| s.trim())
                .find(|s| s.starts_with("authere_refresh="))
                .and_then(|s| s.strip_prefix("authere_refresh="))
                .map(|s| s.to_owned())
        })
        .ok_or(AppError::AuthenticationRequired)?;

    let user_id = verify_and_revoke_refresh_token(&refresh_token_str, &mut conn).await?;

    let user = User::get(user_id, &mut conn)
        .await?
        .ok_or(AppError::AuthenticationRequired)?;
    let roles = user.get_roles(&mut conn).await?;
    let token_pair = generate_token_pair(user_id, roles, &mut conn).await?;

    let _ = log_token_refresh(user_id, &ip_str, &mut conn).await;

    let access_cookie = build_auth_cookie(&token_pair.access_token, token_pair.expires_in);
    let refresh_cookie = build_refresh_cookie(
        &token_pair.refresh_token,
        crate::user::auth::token::REFRESH_TOKEN_LIFETIME,
    );

    let mut response_headers = HeaderMap::new();
    response_headers.insert(axum::http::header::SET_COOKIE, access_cookie.parse().unwrap());
    response_headers.append(axum::http::header::SET_COOKIE, refresh_cookie.parse().unwrap());

    Ok((StatusCode::OK, response_headers, axum::Json(serde_json::json!({ "ok": true }))).into_response())
}

// ============================================================================
// Admin UI endpoints
// ============================================================================

#[derive(Serialize, ToSchema)]
struct MeResponse {
    user_id: String,
    roles: Vec<String>,
}

#[utoipa::path(
    get,
    path = "/me",
    responses(
        (status = 200, description = "Current user info", body = MeResponse),
        (status = 401, description = "Authentication required"),
    ),
    tag = AUTH_TAG,
)]
async fn get_me(auth: AuthUser) -> axum::Json<MeResponse> {
    axum::Json(MeResponse {
        user_id: auth.user_id.to_string(),
        roles: auth.roles,
    })
}

#[derive(Deserialize)]
struct AuditLogParams {
    limit: Option<i64>,
    offset: Option<i64>,
}

#[utoipa::path(
    get,
    path = "/audit",
    responses(
        (status = 200, description = "Audit log entries"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin required"),
    ),
    tag = ADMIN_TAG,
)]
async fn get_audit_log(
    _admin: AdminUser,
    State(state): State<AppState>,
    Query(params): Query<AuditLogParams>,
) -> Result<axum::Json<Vec<AuditLogRecord>>, AppError> {
    let limit = params.limit.unwrap_or(50).clamp(1, 200);
    let offset = params.offset.unwrap_or(0).max(0);
    let mut conn = state.db_pool.acquire().await?;
    let records = list_audit_log(limit, offset, &mut conn).await?;
    Ok(axum::Json(records))
}

// ============================================================================
// Registration
// ============================================================================

#[derive(Debug, Deserialize, ToSchema)]
pub struct RegisterInput {
    pub username: String,
    pub name: String,
    pub email: Option<String>,
    pub password: String,
    pub confirm_password: String,
    pub invite_code: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ValidateInviteQuery {
    pub code: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ValidateInviteResponse {
    pub valid: bool,
}

#[utoipa::path(
    post,
    path = "/register",
    request_body(content = RegisterInput),
    responses(
        (status = 200, description = "Registration successful, cookies set"),
        (status = 400, description = "Invalid input, registration closed, or invalid invite"),
        (status = 409, description = "Username already taken"),
        (status = 429, description = "Too many registration attempts"),
        (status = 500, description = "Internal server error")
    ),
    tag = AUTH_TAG,
)]
async fn register(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    extract::Json(input): extract::Json<RegisterInput>,
) -> Result<Response, RegisterError> {
    let client_ip = addr.ip();
    let ip_str = client_ip.to_string();

    if let Err(retry_after) = state.register_rate_limiter.check(client_ip).await {
        return Err(RegisterError::RateLimit(RateLimitExceeded { retry_after }));
    }

    if input.password != input.confirm_password {
        return Err(AppError::InputError(vec!["Passwords do not match".to_string()]).into());
    }

    let create_input = CreateUserInput {
        username: input.username.clone(),
        name: input.name.clone(),
        email: input.email.clone(),
        password: input.password.clone(),
    };
    User::validate_create_input(&create_input)?;

    let mut conn = state.db_pool.acquire().await?;
    let open = open_registration_enabled(&mut conn).await?;

    if !open {
        let code = input.invite_code.as_deref().ok_or_else(|| {
            AppError::InputError(vec!["Registration is by invitation only".to_string()])
        })?;

        let invite = Invitation::get(code, &mut conn)
            .await?
            .ok_or_else(|| AppError::InputError(vec!["Invitation is invalid or expired".to_string()]))?;

        if !invite.is_valid() {
            return Err(AppError::InputError(vec!["Invitation is invalid or expired".to_string()]).into());
        }
    }

    let user = User::new(input.username, input.name, input.email);
    let authenticator = Authenticator::new_password(input.password, user.id).map_err(|e| {
        AppError::InternalError(format!("Failed to create authenticator ({e})"))
    })?;

    let mut tx = state.db_pool.begin().await?;

    let consumed_invite = if !open {
        let code = input.invite_code.as_deref().unwrap();
        let consumed = Invitation::consume(code, &mut tx).await?.ok_or_else(|| {
            AppError::InputError(vec!["Invitation is invalid or expired".to_string()])
        })?;
        Some(consumed)
    } else {
        None
    };

    user.save(&mut tx).await?;
    authenticator.save(&mut tx).await?;

    if let Some(user_role) = Role::get_by_name("user", &mut tx).await? {
        let _ = UserRole::assign(user.id, user_role.id, &mut tx).await;
    }

    tx.commit().await?;

    let invite_id = consumed_invite.as_ref().map(|i| i.id.as_str());
    let _ = log_user_registered(user.id, invite_id, &ip_str, &mut conn).await;
    if let Some(invite) = &consumed_invite {
        let _ = log_invitation_consumed(user.id, &invite.id, &ip_str, &mut conn).await;
    }

    let token_pair = generate_token_pair(user.id, vec!["user".to_string()], &mut conn).await?;

    let access_cookie = build_auth_cookie(&token_pair.access_token, token_pair.expires_in);
    let refresh_cookie = build_refresh_cookie(
        &token_pair.refresh_token,
        crate::user::auth::token::REFRESH_TOKEN_LIFETIME,
    );

    let mut headers = axum::http::header::HeaderMap::new();
    headers.insert(
        axum::http::header::SET_COOKIE,
        access_cookie.parse().unwrap(),
    );
    headers.append(
        axum::http::header::SET_COOKIE,
        refresh_cookie.parse().unwrap(),
    );

    Ok((
        StatusCode::OK,
        headers,
        axum::Json(BrowserLoginResponse {
            success: true,
            redirect_uri: Some("/account".to_string()),
        }),
    )
        .into_response())
}

#[utoipa::path(
    get,
    path = "/register/validate-invite",
    params(
        ("code" = String, Query, description = "Invitation code to validate")
    ),
    responses(
        (status = 200, description = "Validation result", body = ValidateInviteResponse),
    ),
    tag = AUTH_TAG,
)]
async fn validate_invite(
    State(state): State<AppState>,
    Query(query): Query<ValidateInviteQuery>,
) -> Result<axum::Json<ValidateInviteResponse>, AppError> {
    let mut conn = state.db_pool.acquire().await?;
    let valid = match Invitation::get(&query.code, &mut conn).await? {
        Some(invite) => invite.is_valid(),
        None => false,
    };
    Ok(axum::Json(ValidateInviteResponse { valid }))
}

// ============================================================================
// Admin: Settings
// ============================================================================

#[utoipa::path(
    get,
    path = "/admin/settings",
    responses(
        (status = 200, description = "Current system settings", body = SettingsResponse),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin required"),
    ),
    tag = ADMIN_TAG,
)]
async fn get_settings(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<axum::Json<SettingsResponse>, AppError> {
    let mut conn = state.db_pool.acquire().await?;
    let open_registration = open_registration_enabled(&mut conn).await?;
    Ok(axum::Json(SettingsResponse { open_registration }))
}

#[utoipa::path(
    patch,
    path = "/admin/settings",
    request_body(content = UpdateSettingsInput),
    responses(
        (status = 200, description = "Updated settings", body = SettingsResponse),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin required"),
    ),
    tag = ADMIN_TAG,
)]
async fn update_settings(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    admin: AdminUser,
    extract::Json(input): extract::Json<UpdateSettingsInput>,
) -> Result<axum::Json<SettingsResponse>, AppError> {
    let ip_str = addr.ip().to_string();
    let mut conn = state.db_pool.acquire().await?;

    let mut changes = serde_json::json!({});

    if let Some(open_reg) = input.open_registration {
        let val = if open_reg { "true" } else { "false" };
        set_setting("open_registration", val, &mut conn).await?;
        changes["open_registration"] = serde_json::json!(open_reg);
    }

    let _ = log_settings_updated(admin.0.user_id, changes, &ip_str, &mut conn).await;

    let open_registration = open_registration_enabled(&mut conn).await?;
    Ok(axum::Json(SettingsResponse { open_registration }))
}

// ============================================================================
// Admin: Invitations
// ============================================================================

#[utoipa::path(
    get,
    path = "/admin/invitations",
    responses(
        (status = 200, description = "List of invitations"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin required"),
    ),
    tag = ADMIN_TAG,
)]
async fn list_invitations(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<axum::Json<Vec<InvitationWithStatus>>, AppError> {
    let mut conn = state.db_pool.acquire().await?;
    let invitations = Invitation::list(&mut conn).await?;
    Ok(axum::Json(invitations))
}

#[utoipa::path(
    post,
    path = "/admin/invitations",
    request_body(content = CreateInvitationInput),
    responses(
        (status = 201, description = "Created invitation"),
        (status = 400, description = "Invalid input"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin required"),
    ),
    tag = ADMIN_TAG,
)]
async fn create_invitation(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    admin: AdminUser,
    extract::Json(input): extract::Json<CreateInvitationInput>,
) -> Result<(StatusCode, axum::Json<Invitation>), AppError> {
    let ip_str = addr.ip().to_string();
    Invitation::validate_input(&input)?;

    let invitation = Invitation::new(input, admin.0.user_id);
    let mut conn = state.db_pool.acquire().await?;
    invitation.save(&mut conn).await?;

    let _ = log_invitation_created(admin.0.user_id, &invitation.id, invitation.label.as_deref(), &ip_str, &mut conn).await;

    Ok((StatusCode::CREATED, axum::Json(invitation)))
}

#[utoipa::path(
    delete,
    path = "/admin/invitations/{id}",
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
async fn delete_invitation(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    admin: AdminUser,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    let ip_str = addr.ip().to_string();
    let mut conn = state.db_pool.acquire().await?;

    let deleted = Invitation::delete(&id, &mut conn).await?;
    if !deleted {
        return Err(AppError::NotFound);
    }

    let _ = log_invitation_deleted(admin.0.user_id, &id, &ip_str, &mut conn).await;

    Ok(StatusCode::NO_CONTENT)
}

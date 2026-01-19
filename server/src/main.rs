use std::env;
use std::net::SocketAddr;
use std::time::Duration;

use crate::application::{Application, CreateApplicationInput, UpdateApplicationInput};
use crate::audit::{log_login_failed, log_login_success, log_logout, log_token_refresh, log_user_created};
use crate::auth_middleware::AdminUser;
use crate::cli::{Cli, Commands};
use crate::db::DbEntity;
use crate::errors::AppError;
use crate::rate_limit::{RateLimitConfig, RateLimitExceeded, RateLimiter};
use crate::role::{CreateRoleInput, Role, UserRole};
use crate::user::auth::token::{self, TokenPair, generate_token_pair, verify_access_token, verify_refresh_token, revoke_refresh_token};
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
pub mod rate_limit;
pub mod role;
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

#[tokio::main]
async fn main() -> Result<(), AppError> {
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

    let state = AppState {
        db_pool,
        login_rate_limiter,
    };

    let (router, api) = OpenApiRouter::with_openapi(ApiDoc::openapi())
        .routes(routes!(create_user, get_users))
        .routes(routes!(get_user))
        .routes(routes!(login))
        .routes(routes!(refresh_token))
        .routes(routes!(logout))
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
        .with_state(state)
        .split_for_parts();

    let router = router.merge(SwaggerUi::new("/docs").url("/apidoc/openapi.json", api));

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
    tx.commit().await?;

    // Log user creation (no actor_id since this is self-registration or unauthenticated)
    let mut conn = state.db_pool.acquire().await?;
    let _ = log_user_created(user.id, None, &ip_str, &mut conn).await;

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
            // Record the failure for rate limiting purposes
            state.login_rate_limiter.record_failure(client_ip).await;
            // Log the failed login attempt
            let _ = log_login_failed(&username, &ip_str, ua_str, &mut conn).await;
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

    // Verify the refresh token and get the user ID
    let user_id = verify_refresh_token(&input.refresh_token, &mut conn).await?;

    // Revoke the old refresh token (rotation)
    revoke_refresh_token(&input.refresh_token, &mut conn).await?;

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

    // Verify the refresh token to get the user ID for logging
    let user_id = verify_refresh_token(&input.refresh_token, &mut conn).await?;

    // Revoke the refresh token
    revoke_refresh_token(&input.refresh_token, &mut conn).await?;

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
    _admin: AdminUser,
    Path(user_id): Path<Uuid>,
    extract::Json(input): extract::Json<AssignRoleInput>,
) -> Result<StatusCode, AppError> {
    let mut conn = state.db_pool.acquire().await?;

    // Check user exists
    let user = User::get(user_id, &mut conn).await?;
    if user.is_none() {
        return Err(AppError::NotFound);
    }

    // Check role exists
    let role = Role::get(input.role_id, &mut conn).await?;
    if role.is_none() {
        return Err(AppError::NotFound);
    }

    UserRole::assign(user_id, input.role_id, &mut conn).await?;
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
    _admin: AdminUser,
    Path((user_id, role_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    let mut conn = state.db_pool.acquire().await?;

    let removed = UserRole::remove(user_id, role_id, &mut conn).await?;
    if removed {
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
            let _ = log_login_failed(&username, &ip_str, ua_str, &mut conn).await;
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
        if let Ok(user_id) = verify_refresh_token(token, &mut conn).await {
            let _ = revoke_refresh_token(token, &mut conn).await;
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

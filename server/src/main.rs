use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::FromRef;
use axum::http;
use clap::Parser;
use ed25519_dalek::SigningKey;
use sqlx::SqlitePool;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use utoipa_swagger_ui::SwaggerUi;

use crate::cli::{Cli, Commands};
use crate::errors::AppError;
use crate::rate_limit::{RateLimitConfig, RateLimiter};
use crate::user::auth::token;

pub mod application;
pub mod audit;
pub mod auth_middleware;
pub mod cli;
pub mod db;
pub mod errors;
pub mod handlers;
pub mod invitation;
pub mod rate_limit;
pub mod role;
pub mod settings;
pub mod static_files;
pub mod user;

const ADMIN_TAG: &str = "admin";
const AUTH_TAG: &str = "auth";

#[derive(OpenApi)]
#[openapi(
    tags(
        (name = ADMIN_TAG, description = "Admin API endpoints"),
        (name = AUTH_TAG, description = "Authentication API endpoints")
    )
)]
struct ApiDoc;

#[derive(Clone)]
pub struct AppState {
    pub db_pool: SqlitePool,
    pub login_rate_limiter: RateLimiter,
    pub register_rate_limiter: RateLimiter,
    pub signing_key: Arc<SigningKey>,
}

impl FromRef<AppState> for SqlitePool {
    fn from_ref(state: &AppState) -> Self {
        state.db_pool.clone()
    }
}

impl FromRef<AppState> for Arc<SigningKey> {
    fn from_ref(state: &AppState) -> Self {
        state.signing_key.clone()
    }
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| {
        warn!("DATABASE_URL not set, using default: sqlite:./data.db");
        String::from("sqlite:./data.db")
    });
    let db_pool = SqlitePool::connect(&database_url)
        .await
        .expect("Could not connect to sqlite!");

    let mut conn = db_pool.acquire().await?;
    token::try_initialize(&mut conn).await?;

    let signing_key = Arc::new(token::load_signing_key(&mut conn).await?);
    info!("signing key loaded and cached");
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
        Some(Commands::Serve) | None => {}
    }

    let login_rate_limiter = RateLimiter::new(RateLimitConfig {
        max_requests: 5,
        window: Duration::from_secs(60),
    });

    let register_rate_limiter = RateLimiter::new(RateLimitConfig {
        max_requests: 3,
        window: Duration::from_secs(3600),
    });

    // Spawn background cleanup for rate limiters
    {
        let login_rl = login_rate_limiter.clone();
        let register_rl = register_rate_limiter.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300));
            loop {
                interval.tick().await;
                login_rl.cleanup().await;
                register_rl.cleanup().await;
                tracing::debug!("rate limiter cleanup completed");
            }
        });
    }

    let state = AppState {
        db_pool,
        login_rate_limiter,
        register_rate_limiter,
        signing_key,
    };

    use crate::handlers::{admin, application, auth, registration, role, user};

    let (router, api) = OpenApiRouter::with_openapi(ApiDoc::openapi())
        .routes(routes!(user::create_user, user::get_users))
        .routes(routes!(user::get_user, user::update_user))
        .routes(routes!(auth::login))
        .routes(routes!(auth::refresh_token))
        .routes(routes!(auth::logout))
        // Registration
        .routes(routes!(registration::register))
        .routes(routes!(registration::validate_invite))
        // Role management
        .routes(routes!(role::list_roles))
        .routes(routes!(role::create_role))
        .routes(routes!(role::delete_role))
        // User role management
        .routes(routes!(role::get_user_roles))
        .routes(routes!(role::assign_role))
        .routes(routes!(role::remove_role))
        // Application management
        .routes(routes!(application::list_applications))
        .routes(routes!(application::create_application))
        .routes(routes!(application::get_application))
        .routes(routes!(application::update_application))
        .routes(routes!(application::delete_application))
        // Forward auth
        .routes(routes!(auth::verify_auth))
        // Browser-friendly auth
        .routes(routes!(auth::browser_login))
        .routes(routes!(auth::browser_logout))
        .routes(routes!(auth::browser_refresh))
        // User self-service
        .routes(routes!(user::get_me, user::update_me))
        .routes(routes!(user::change_my_password))
        .routes(routes!(user::admin_change_user_password))
        .routes(routes!(admin::get_audit_log))
        // Admin settings
        .routes(routes!(admin::get_settings, admin::update_settings))
        // Admin invitations
        .routes(routes!(admin::list_invitations, admin::create_invitation))
        .routes(routes!(admin::delete_invitation))
        .with_state(state)
        .split_for_parts();

    let mut router = router;
    if cfg!(debug_assertions) || env::var("AUTHERE_SWAGGER_ENABLED").is_ok() {
        router = router.merge(SwaggerUi::new("/docs").url("/apidoc/openapi.json", api));
    }

    let router = router
        .route("/assets/{*path}", axum::routing::get(static_files::serve_asset))
        .route("/", axum::routing::get(static_files::serve_spa))
        .route("/login", axum::routing::get(static_files::serve_spa))
        .route("/admin", axum::routing::get(static_files::serve_spa))
        .route("/admin/{*path}", axum::routing::get(static_files::serve_spa))
        .route("/account", axum::routing::get(static_files::serve_spa))
        .route("/credentials", axum::routing::get(static_files::serve_spa))
        .route("/register", axum::routing::get(static_files::serve_spa));

    // CORS
    let cors = if let Ok(origins) = env::var("AUTHERE_ALLOWED_ORIGINS") {
        let allowed: Vec<http::HeaderValue> = origins
            .split(',')
            .filter_map(|o| o.trim().parse().ok())
            .collect();
        tower_http::cors::CorsLayer::new()
            .allow_origin(allowed)
            .allow_methods([http::Method::GET, http::Method::POST, http::Method::PUT, http::Method::DELETE])
            .allow_headers([http::header::CONTENT_TYPE, http::header::AUTHORIZATION])
            .allow_credentials(true)
    } else {
        tower_http::cors::CorsLayer::new()
            .allow_origin(tower_http::cors::AllowOrigin::exact("null".parse().unwrap()))
            .allow_methods([http::Method::GET, http::Method::POST, http::Method::PUT, http::Method::DELETE])
            .allow_headers([http::header::CONTENT_TYPE, http::header::AUTHORIZATION])
    };

    // Request tracing
    let trace_layer = tower_http::trace::TraceLayer::new_for_http()
        .make_span_with(tower_http::trace::DefaultMakeSpan::new().level(tracing::Level::INFO))
        .on_response(tower_http::trace::DefaultOnResponse::new().level(tracing::Level::INFO));

    let router = router.layer(cors).layer(trace_layer);

    info!("starting server on 0.0.0.0:3000");

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    Ok(axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()).await?)
}

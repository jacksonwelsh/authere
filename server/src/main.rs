use std::env;
use std::net::SocketAddr;
use std::process::ExitCode;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use axum::http;
use clap::Parser;
use sqlx::SqlitePool;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use utoipa_swagger_ui::SwaggerUi;

use authere_server::AppState;
use authere_server::cli::{self, Cli, Commands};
use authere_server::errors::AppError;
use authere_server::rate_limit::{RateLimitConfig, RateLimiter};
use authere_server::static_files;
use authere_server::user::auth::token;

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

const EXIT_RESTART: u8 = 75;

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(restart) => {
            if restart {
                ExitCode::from(EXIT_RESTART)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(e) => {
            eprintln!("fatal: {e:?}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<bool, AppError> {
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
    let connect_opts = sqlx::sqlite::SqliteConnectOptions::from_str(&database_url)
        .expect("Invalid DATABASE_URL")
        .create_if_missing(true);
    let db_pool = SqlitePool::connect_with(connect_opts)
        .await
        .expect("Could not connect to sqlite!");

    sqlx::migrate!("../migrations")
        .run(&db_pool)
        .await
        .expect("Failed to run database migrations");
    info!("database migrations applied");

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
            return Ok(false);
        }
        Some(Commands::Serve) | None => {}
    }

    fn env_override(name: &str, default: u32) -> u32 {
        env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
    }

    let login_rate_limiter = RateLimiter::new(RateLimitConfig {
        max_requests: env_override("AUTHERE_LOGIN_MAX_REQUESTS", 5),
        window: Duration::from_secs(env_override("AUTHERE_LOGIN_WINDOW_SECS", 60).into()),
    });

    let register_rate_limiter = RateLimiter::new(RateLimitConfig {
        max_requests: env_override("AUTHERE_REGISTER_MAX_REQUESTS", 3),
        window: Duration::from_secs(env_override("AUTHERE_REGISTER_WINDOW_SECS", 3600).into()),
    });

    let ldap_bind_rate_limiter = RateLimiter::new(RateLimitConfig {
        max_requests: env_override("AUTHERE_LDAP_MAX_REQUESTS", 30),
        window: Duration::from_secs(env_override("AUTHERE_LDAP_WINDOW_SECS", 60).into()),
    });

    let scim_rate_limiter = RateLimiter::new(RateLimitConfig {
        max_requests: env_override("AUTHERE_SCIM_MAX_REQUESTS", 60),
        window: Duration::from_secs(env_override("AUTHERE_SCIM_WINDOW_SECS", 60).into()),
    });

    // Spawn background cleanup for rate limiters
    {
        let login_rl = login_rate_limiter.clone();
        let register_rl = register_rate_limiter.clone();
        let ldap_rl = ldap_bind_rate_limiter.clone();
        let scim_rl = scim_rate_limiter.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300));
            loop {
                interval.tick().await;
                login_rl.cleanup().await;
                register_rl.cleanup().await;
                ldap_rl.cleanup().await;
                scim_rl.cleanup().await;
                tracing::debug!("rate limiter cleanup completed");
            }
        });
    }

    let origin = env::var("AUTHERE_ORIGIN").unwrap_or_else(|_| {
        warn!("AUTHERE_ORIGIN not set — forward auth redirects will use http://localhost:3000");
        String::from("http://localhost:3000")
    });

    let shutdown = Arc::new(tokio::sync::Notify::new());

    let provisioning_notifier = authere_server::provisioning::Notifier::new();

    let state = AppState {
        db_pool,
        login_rate_limiter,
        register_rate_limiter,
        ldap_bind_rate_limiter,
        scim_rate_limiter,
        signing_key,
        origin,
        shutdown,
        provisioning_notifier: provisioning_notifier.clone(),
    };

    // Start the outbound-provisioning worker. If AUTHERE_PROVISIONING_KEY isn't set the
    // worker can't decrypt target tokens, so we don't spawn it — admins who want this
    // feature supply the key; other deployments run unaffected.
    match authere_server::provisioning::targets::load_master_key() {
        Ok(key) => {
            let pool = state.db_pool.clone();
            let notifier = provisioning_notifier.clone();
            let http = reqwest::Client::builder()
                .build()
                .expect("failed to build reqwest client");
            tokio::spawn(async move {
                authere_server::provisioning::worker::run(pool, notifier, key, http).await;
            });
            info!("outbound provisioning worker started");
        }
        Err(e) => {
            warn!(error = ?e, "outbound provisioning disabled");
        }
    }

    // Start the LDAP listener if enabled. Settings changes take effect on the next
    // restart — rebinding to a different port at runtime is out of scope for the MVP.
    {
        let mut conn = state.db_pool.acquire().await?;
        let ldap_cfg = authere_server::settings::load_ldap_config(&mut conn).await?;
        drop(conn);
        if ldap_cfg.enabled {
            if ldap_cfg.service_password_hash.is_none() {
                warn!(
                    addr = %ldap_cfg.bind_address,
                    "ldap enabled but service bind password is not set — users can still bind"
                );
            }
            let ldap_state = state.clone();
            tokio::spawn(async move {
                if let Err(e) = authere_server::ldap::run(ldap_state).await {
                    tracing::error!(error = %e, "ldap listener terminated");
                }
            });
        } else {
            info!("ldap disabled");
        }
    }

    use authere_server::handlers::{admin, app_passwords, application, auth, registration, role, totp, user};
    use authere_server::provisioning::admin as provisioning_admin;
    use authere_server::scim;

    let shutdown_handle = state.shutdown.clone();

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
        .routes(routes!(auth::forward_redirect))
        .routes(routes!(auth::forward_auth_callback))
        // Browser-friendly auth
        .routes(routes!(auth::browser_login))
        .routes(routes!(auth::browser_logout))
        .routes(routes!(auth::browser_refresh))
        // User self-service
        .routes(routes!(user::get_me, user::update_me))
        .routes(routes!(user::change_my_password))
        .routes(routes!(user::admin_change_user_password))
        .routes(routes!(admin::get_audit_log))
        .routes(routes!(admin::get_audit_event_types))
        .routes(routes!(admin::export_audit_log))
        // Admin settings
        .routes(routes!(admin::get_settings, admin::update_settings))
        .routes(routes!(admin::regenerate_ldap_bind_password))
        .routes(routes!(admin::restart_service))
        // Admin invitations
        .routes(routes!(admin::list_invitations, admin::create_invitation))
        .routes(routes!(admin::delete_invitation))
        // TOTP (user self-service + admin force-disable)
        .routes(routes!(totp::get_my_totp_status, totp::disable_my_totp))
        .routes(routes!(totp::enroll_my_totp))
        .routes(routes!(totp::activate_my_totp))
        .routes(routes!(totp::admin_disable_user_totp))
        // App passwords (user self-service)
        .routes(routes!(
            app_passwords::list_my_app_passwords,
            app_passwords::create_my_app_password
        ))
        .routes(routes!(app_passwords::delete_my_app_password))
        // App passwords (admin)
        .routes(routes!(app_passwords::admin_list_app_passwords))
        .routes(routes!(app_passwords::admin_delete_app_password))
        // SCIM admin token management (uses AdminUser JWT auth)
        .routes(routes!(
            scim::admin::create_scim_token,
            scim::admin::list_scim_tokens
        ))
        .routes(routes!(scim::admin::revoke_scim_token))
        // SCIM 2.0 discovery
        .routes(routes!(scim::discovery::service_provider_config))
        .routes(routes!(scim::discovery::list_resource_types))
        .routes(routes!(scim::discovery::get_resource_type))
        .routes(routes!(scim::discovery::list_schemas))
        .routes(routes!(scim::discovery::get_schema))
        // SCIM 2.0 Users
        .routes(routes!(scim::users::list_users, scim::users::create_user))
        .routes(routes!(scim::users::search_users))
        .routes(routes!(scim::users::search_root))
        .routes(routes!(
            scim::users::get_user,
            scim::users::replace_user,
            scim::users::patch_user,
            scim::users::delete_user
        ))
        // Outbound provisioning (admin-only CRUD + job observability)
        .routes(routes!(
            provisioning_admin::create_target,
            provisioning_admin::list_targets
        ))
        .routes(routes!(
            provisioning_admin::update_target,
            provisioning_admin::delete_target
        ))
        .routes(routes!(provisioning_admin::list_jobs))
        .routes(routes!(provisioning_admin::retry_job))
        .with_state(state)
        .split_for_parts();

    let mut router = router;
    if cfg!(debug_assertions) || env::var("AUTHERE_SWAGGER_ENABLED").is_ok() {
        router = router.merge(SwaggerUi::new("/docs").url("/apidoc/openapi.json", api));
    }

    // SCIM 2.0 catch-all: any unknown path under /scim/v2 must still return a spec-shaped
    // error (application/scim+json body, Error URN, string status). Without this, axum's
    // default 404 produces a plain-text "not found" that trips compliance testers.
    let router = router.route(
        "/scim/v2/{*rest}",
        axum::routing::any(|| async { authere_server::scim::error::ScimError::not_found() }),
    );

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

    let bind_addr =
        env::var("AUTHERE_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:3000".to_string());
    info!("starting server on {bind_addr}");

    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(async move { shutdown_handle.notified().await })
        .await?;

    info!("server stopped, exiting with restart code {EXIT_RESTART}");
    Ok(true)
}

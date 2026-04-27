//! Integration tests for `GET /api/auth/forward-app` — the public endpoint
//! the login page calls to display "Sign in to continue to {appName}".

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use ed25519_dalek::SigningKey;
use sqlx::SqlitePool;
use sqlx::sqlite::SqlitePoolOptions;
use tower::ServiceExt;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use authere_server::AppState;
use authere_server::application::{AppType, Application, CreateApplicationInput};
use authere_server::db::DbEntity;
use authere_server::handlers::auth;
use authere_server::rate_limit::{RateLimitConfig, RateLimiter};

async fn pool() -> SqlitePool {
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::migrate!("../migrations").run(&pool).await.unwrap();
    pool
}

async fn setup() -> Router {
    let pool = pool().await;
    let mut conn = pool.acquire().await.unwrap();

    let app = Application::new(CreateApplicationInput {
        name: "Flood Tracker".into(),
        slug: "flood".into(),
        app_type: Some(AppType::ForwardAuth),
        host_pattern: Some("flood.example.com".into()),
        path_prefix: None,
        required_roles: None,
        enabled: Some(true),
        oidc_redirect_uris: None,
        oidc_post_logout_redirect_uris: None,
        oidc_confidential: None,
    });
    app.save(&mut conn).await.unwrap();

    // Disabled forward_auth app — should NOT be matched.
    let mut disabled = Application::new(CreateApplicationInput {
        name: "Old App".into(),
        slug: "old".into(),
        app_type: Some(AppType::ForwardAuth),
        host_pattern: Some("old.example.com".into()),
        path_prefix: None,
        required_roles: None,
        enabled: Some(false),
        oidc_redirect_uris: None,
        oidc_post_logout_redirect_uris: None,
        oidc_confidential: None,
    });
    disabled.enabled = false;
    disabled.save(&mut conn).await.unwrap();

    // OIDC app sharing a host with no forward_auth peer — also should NOT match
    // (lookup is forward_auth-only).
    let (oidc_app, _) = Application::new_oidc(CreateApplicationInput {
        name: "Some OIDC RP".into(),
        slug: "oidc-rp".into(),
        app_type: Some(AppType::Oidc),
        host_pattern: None,
        path_prefix: None,
        required_roles: None,
        enabled: Some(true),
        oidc_redirect_uris: Some(vec!["https://oidc.example.com/cb".into()]),
        oidc_post_logout_redirect_uris: None,
        oidc_confidential: Some(true),
    });
    oidc_app.save(&mut conn).await.unwrap();

    drop(conn);

    let signing_key = Arc::new(SigningKey::generate(&mut rand::rngs::OsRng));
    let state = AppState {
        db_pool: pool,
        login_rate_limiter: RateLimiter::new(RateLimitConfig::default()),
        register_rate_limiter: RateLimiter::new(RateLimitConfig::default()),
        ldap_bind_rate_limiter: RateLimiter::new(RateLimitConfig::default()),
        scim_rate_limiter: RateLimiter::new(RateLimitConfig::default()),
        oidc_token_rate_limiter: RateLimiter::new(RateLimitConfig {
            max_requests: 10_000,
            window: Duration::from_secs(60),
        }),
        signing_key,
        signing_kid: "test-kid".into(),
        origin: "https://authere.example".into(),
        shutdown: Arc::new(tokio::sync::Notify::new()),
        provisioning_notifier: authere_server::provisioning::Notifier::new(),
    };

    let (router, _) = OpenApiRouter::new()
        .routes(routes!(auth::lookup_forward_app))
        .with_state(state)
        .split_for_parts();
    router
}

async fn body_json(resp: Response<Body>) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1_000_000).await.unwrap();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::json!(null))
}

fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn returns_app_name_for_matching_forward_auth_host() {
    let router = setup().await;
    let resp = router
        .oneshot(get(
            "/api/auth/forward-app?redirect_uri=https%3A%2F%2Fflood.example.com%2Fdashboard",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["name"], "Flood Tracker");
}

#[tokio::test]
async fn returns_404_for_unknown_host() {
    let router = setup().await;
    let resp = router
        .oneshot(get(
            "/api/auth/forward-app?redirect_uri=https%3A%2F%2Funknown.example.com%2F",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn skips_disabled_apps() {
    let router = setup().await;
    let resp = router
        .oneshot(get(
            "/api/auth/forward-app?redirect_uri=https%3A%2F%2Fold.example.com%2F",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn skips_oidc_apps() {
    // Even though the OIDC app exists, the lookup is forward_auth-only —
    // the host is "oidc.example.com" but no forward_auth app claims it.
    let router = setup().await;
    let resp = router
        .oneshot(get(
            "/api/auth/forward-app?redirect_uri=https%3A%2F%2Foidc.example.com%2F",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn rejects_malformed_redirect_uri() {
    let router = setup().await;
    let resp = router
        .oneshot(get("/api/auth/forward-app?redirect_uri=not-a-url"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn rejects_redirect_uri_without_host() {
    let router = setup().await;
    // file:// URLs parse but have no host — guard against that.
    let resp = router
        .oneshot(get(
            "/api/auth/forward-app?redirect_uri=file%3A%2F%2F%2Ftmp%2Ffoo",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

//! Shared fixture for SCIM integration tests: in-memory DB, seeded users, minted SCIM token,
//! and a router that hosts only the SCIM + SCIM-admin routes (no UI, no LDAP listener).

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, Response};
use ed25519_dalek::SigningKey;
use sqlx::SqlitePool;
use sqlx::sqlite::SqlitePoolOptions;
use tower::ServiceExt;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;

use authere_server::AppState;
use authere_server::db::DbEntity;
use authere_server::rate_limit::{RateLimitConfig, RateLimiter};
use authere_server::scim;
use authere_server::user::User;

#[allow(dead_code)]
pub const SCIM_CONTENT_TYPE: &str = "application/scim+json; charset=utf-8";

#[allow(dead_code)]
pub struct Fixture {
    pub router: Router,
    pub pool: SqlitePool,
    pub scim_token: String,
    pub alice_id: Uuid,
    pub bob_id: Uuid,
}

pub async fn new_pool() -> SqlitePool {
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect("sqlite::memory:")
        .await
        .expect("open in-memory sqlite");
    sqlx::migrate!("../migrations")
        .run(&pool)
        .await
        .expect("run migrations");
    pool
}

/// Seed two users (alice active, bob active+inactive variants are set by tests) plus a
/// freshly-minted SCIM token. The token is returned so tests can present it as a bearer.
pub async fn setup() -> Fixture {
    let pool = new_pool().await;
    let mut conn = pool.acquire().await.unwrap();

    let mut alice = User::new("alice".into(), "Alice Example".into(), Some("alice@example.com".into()));
    alice.external_id = Some("okta-alice".into());
    alice.save(&mut conn).await.unwrap();

    let bob = User::new("bob".into(), "Bob Example".into(), Some("bob@example.com".into()));
    bob.save(&mut conn).await.unwrap();

    // An admin who owns the SCIM token — the FK requires a real user. We don't use this
    // account for login in SCIM tests.
    let admin = User::new("scim-admin".into(), "SCIM Admin".into(), None);
    admin.save(&mut conn).await.unwrap();

    let minted = scim::token::mint("test-token", admin.id, &mut conn)
        .await
        .expect("mint scim token");
    drop(conn);

    let signing_key = Arc::new(SigningKey::generate(&mut rand::rngs::OsRng));
    let state = AppState {
        db_pool: pool.clone(),
        login_rate_limiter: RateLimiter::new(RateLimitConfig::default()),
        register_rate_limiter: RateLimiter::new(RateLimitConfig::default()),
        ldap_bind_rate_limiter: RateLimiter::new(RateLimitConfig::default()),
        scim_rate_limiter: RateLimiter::new(RateLimitConfig {
            max_requests: 10_000,
            window: Duration::from_secs(60),
        }),
        signing_key,
        origin: "http://localhost:3000".to_string(),
    };

    let (router, _) = OpenApiRouter::new()
        .routes(routes!(scim::discovery::service_provider_config))
        .routes(routes!(scim::discovery::list_resource_types))
        .routes(routes!(scim::discovery::get_resource_type))
        .routes(routes!(scim::discovery::list_schemas))
        .routes(routes!(scim::discovery::get_schema))
        .routes(routes!(scim::users::list_users, scim::users::create_user))
        .routes(routes!(scim::users::search_users))
        .routes(routes!(scim::users::search_root))
        .routes(routes!(
            scim::users::get_user,
            scim::users::replace_user,
            scim::users::patch_user,
            scim::users::delete_user
        ))
        .with_state(state)
        .split_for_parts();

    Fixture {
        router,
        pool,
        scim_token: minted.plaintext,
        alice_id: alice.id,
        bob_id: bob.id,
    }
}

/// Send a GET request with the Bearer header. Returns the raw axum Response for inspection.
pub async fn get_with_token(fx: &Fixture, uri: &str, token: &str) -> Response<Body> {
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    fx.router.clone().oneshot(req).await.unwrap()
}

#[allow(dead_code)]
pub async fn get_no_auth(fx: &Fixture, uri: &str) -> Response<Body> {
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    fx.router.clone().oneshot(req).await.unwrap()
}

pub async fn body_json(resp: Response<Body>) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 2_000_000)
        .await
        .expect("read body");
    serde_json::from_slice(&bytes).unwrap_or(serde_json::json!(null))
}

/// Generic request helper. `extra_headers` lets tests set things like If-Match.
#[allow(dead_code)]
pub async fn request(
    fx: &Fixture,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<serde_json::Value>,
    extra_headers: &[(&str, &str)],
) -> Response<Body> {
    let mut b = Request::builder().method(method).uri(uri);
    if let Some(t) = token {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    let has_body = body.is_some();
    if has_body {
        b = b.header("content-type", "application/scim+json");
    }
    for (k, v) in extra_headers {
        b = b.header(*k, *v);
    }
    let body = match body {
        Some(v) => Body::from(serde_json::to_vec(&v).unwrap()),
        None => Body::empty(),
    };
    let req = b.body(body).unwrap();
    fx.router.clone().oneshot(req).await.unwrap()
}

#[allow(dead_code)]
pub async fn post_json(fx: &Fixture, uri: &str, token: &str, body: serde_json::Value) -> Response<Body> {
    request(fx, "POST", uri, Some(token), Some(body), &[]).await
}

#[allow(dead_code)]
pub async fn put_json(fx: &Fixture, uri: &str, token: &str, body: serde_json::Value) -> Response<Body> {
    request(fx, "PUT", uri, Some(token), Some(body), &[]).await
}

#[allow(dead_code)]
pub async fn patch_json(fx: &Fixture, uri: &str, token: &str, body: serde_json::Value) -> Response<Body> {
    request(fx, "PATCH", uri, Some(token), Some(body), &[]).await
}

#[allow(dead_code)]
pub async fn delete(fx: &Fixture, uri: &str, token: &str) -> Response<Body> {
    request(fx, "DELETE", uri, Some(token), None, &[]).await
}

//! Integration tests for the OIDC provider (/oauth/* + /.well-known/*).
//!
//! Pattern: spin up an in-memory SQLite + a router that mounts exactly the OIDC endpoints
//! plus the application admin CRUD, seed Alice + an OIDC application, and drive the code
//! flow end-to-end. The tests assert on HTTP status + headers rather than decoded response
//! bodies wherever possible, since the important behaviors happen at the transport layer
//! (redirect URIs, error=... query params, Set-Cookie).

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use axum::{Router, middleware};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use sqlx::sqlite::SqlitePoolOptions;
use tower::ServiceExt;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;

use authere_server::AppState;
use authere_server::application::{AppType, Application, CreateApplicationInput};
use authere_server::browser_security::{BrowserSecurity, protect_browser_requests};
use authere_server::db::DbEntity;
use authere_server::handlers::oauth;
use authere_server::rate_limit::{RateLimitConfig, RateLimiter};
use authere_server::role::Role;
use authere_server::user::User;
use authere_server::user::auth::token::{
    generate_access_token, generate_token_pair, revoke_all_user_tokens, verify_access_token,
};

struct Fixture {
    router: Router,
    pool: SqlitePool,
    signing_key: Arc<SigningKey>,
    origin: String,
    alice_id: Uuid,
    session_cookie: String,
    /// OIDC application: confidential client.
    app_id: Uuid,
    client_id: String,
    client_secret: String,
    /// Public client variant.
    public_app_id: Uuid,
    public_client_id: String,
    /// Role-gated application.
    gated_app_id: Uuid,
    gated_client_id: String,
}

async fn pool() -> SqlitePool {
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::migrate!("../migrations").run(&pool).await.unwrap();
    pool
}

async fn setup() -> Fixture {
    let pool = pool().await;
    let mut conn = pool.acquire().await.unwrap();

    let alice = User::new(
        "alice".into(),
        "Alice Example".into(),
        Some("alice@example.com".into()),
    );
    alice.save(&mut conn).await.unwrap();

    // Confidential OIDC client.
    let (app, secret) = Application::new_oidc(CreateApplicationInput {
        name: "RP Confidential".into(),
        slug: "rp".into(),
        app_type: Some(AppType::Oidc),
        host_pattern: None,
        path_prefix: None,
        required_roles: None,
        enabled: Some(true),
        oidc_redirect_uris: Some(vec!["https://rp.example.com/cb".into()]),
        oidc_post_logout_redirect_uris: Some(vec!["https://rp.example.com/logged-out".into()]),
        oidc_confidential: Some(true),
    });
    let app_id = app.id;
    let client_id = app.oidc_client_id.clone().unwrap();
    let client_secret = secret.unwrap();
    app.save(&mut conn).await.unwrap();

    // Public client variant.
    let (pub_app, pub_secret) = Application::new_oidc(CreateApplicationInput {
        name: "RP Public".into(),
        slug: "rp-public".into(),
        app_type: Some(AppType::Oidc),
        host_pattern: None,
        path_prefix: None,
        required_roles: None,
        enabled: Some(true),
        oidc_redirect_uris: Some(vec!["https://spa.example.com/cb".into()]),
        oidc_post_logout_redirect_uris: None,
        oidc_confidential: Some(false),
    });
    assert!(pub_secret.is_none());
    let public_app_id = pub_app.id;
    let public_client_id = pub_app.oidc_client_id.clone().unwrap();
    pub_app.save(&mut conn).await.unwrap();

    // Role-gated client + an "engineer" role Alice does NOT have.
    let engineer = Role::new("engineer".into(), None);
    engineer.save(&mut conn).await.unwrap();
    let (gated, _) = Application::new_oidc(CreateApplicationInput {
        name: "Gated RP".into(),
        slug: "gated-rp".into(),
        app_type: Some(AppType::Oidc),
        host_pattern: None,
        path_prefix: None,
        required_roles: Some(vec![engineer.id.to_string()]),
        enabled: Some(true),
        oidc_redirect_uris: Some(vec!["https://gated.example.com/cb".into()]),
        oidc_post_logout_redirect_uris: None,
        oidc_confidential: Some(true),
    });
    let gated_app_id = gated.id;
    let gated_client_id = gated.oidc_client_id.clone().unwrap();
    gated.save(&mut conn).await.unwrap();

    drop(conn);

    let signing_key = Arc::new(SigningKey::generate(&mut rand::rngs::OsRng));
    let session_cookie = format!(
        "__Host-authere_token={}",
        generate_access_token(alice.id, vec!["user".into()], &signing_key).unwrap(),
    );
    let origin = "https://authere.example".to_string();

    let state = AppState {
        db_pool: pool.clone(),
        login_rate_limiter: RateLimiter::new(RateLimitConfig::default()),
        register_rate_limiter: RateLimiter::new(RateLimitConfig::default()),
        ldap_bind_rate_limiter: RateLimiter::new(RateLimitConfig::default()),
        oidc_token_rate_limiter: RateLimiter::new(RateLimitConfig {
            max_requests: 10_000,
            window: Duration::from_secs(60),
        }),
        signing_key: signing_key.clone(),
        signing_kid: "test-kid".to_string(),
        origin: origin.clone(),
        shutdown: Arc::new(tokio::sync::Notify::new()),
    };

    let (router, _) = OpenApiRouter::new()
        .routes(routes!(oauth::discovery))
        .routes(routes!(oauth::jwks))
        .routes(routes!(oauth::authorize))
        .routes(routes!(oauth::token))
        .routes(routes!(oauth::userinfo))
        .routes(routes!(oauth::end_session))
        .routes(routes!(oauth::end_session_post))
        .with_state(state)
        .split_for_parts();

    Fixture {
        router,
        pool,
        signing_key,
        origin,
        alice_id: alice.id,
        session_cookie,
        app_id,
        client_id,
        client_secret,
        public_app_id,
        public_client_id,
        gated_app_id,
        gated_client_id,
    }
}

async fn body_bytes(resp: Response<Body>) -> Vec<u8> {
    axum::body::to_bytes(resp.into_body(), 2_000_000)
        .await
        .unwrap()
        .to_vec()
}

async fn body_json(resp: Response<Body>) -> serde_json::Value {
    let bytes = body_bytes(resp).await;
    serde_json::from_slice(&bytes).unwrap_or(serde_json::json!(null))
}

fn issue_session_cookie(fx: &Fixture) -> String {
    fx.session_cookie.clone()
}

/// Build a PKCE verifier + S256 challenge pair.
fn make_pkce() -> (String, String) {
    let verifier: String = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".into();
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let challenge = URL_SAFE_NO_PAD.encode(hasher.finalize());
    (verifier, challenge)
}

fn authorize_url(
    client_id: &str,
    redirect: &str,
    challenge: &str,
    state: &str,
    nonce: &str,
) -> String {
    format!(
        "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid+profile+email+roles&state={}&nonce={}&code_challenge={}&code_challenge_method=S256",
        urlencoding::encode(client_id),
        urlencoding::encode(redirect),
        urlencoding::encode(state),
        urlencoding::encode(nonce),
        urlencoding::encode(challenge),
    )
}

fn get_with_cookie(uri: &str, cookie: Option<&str>) -> Request<Body> {
    let mut b = Request::builder().method("GET").uri(uri);
    if let Some(c) = cookie {
        b = b.header("cookie", c);
    }
    b.body(Body::empty()).unwrap()
}

fn post_form(uri: &str, body: &str, extra_headers: &[(&str, &str)]) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/x-www-form-urlencoded");
    for (k, v) in extra_headers {
        b = b.header(*k, *v);
    }
    b.body(Body::from(body.to_string())).unwrap()
}

/// Extract `?code=...` from a Location header.
fn extract_code_from_location(resp: &Response<Body>) -> String {
    let loc = resp.headers().get("location").unwrap().to_str().unwrap();
    let (_, query) = loc.split_once('?').unwrap();
    for pair in query.split('&') {
        if let Some(v) = pair.strip_prefix("code=") {
            return urlencoding::decode(v).unwrap().into_owned();
        }
    }
    panic!("no code in {loc}")
}

fn query_param<'a>(url: &'a str, key: &str) -> Option<String> {
    let (_, query) = url.split_once('?')?;
    for pair in query.split('&') {
        if let Some(v) = pair.strip_prefix(&format!("{key}=")) {
            return Some(urlencoding::decode(v).ok()?.into_owned());
        }
    }
    None
}

// ============================================================================
// Discovery + JWKS
// ============================================================================

#[tokio::test]
async fn discovery_document_has_required_fields() {
    let fx = setup().await;
    let resp = fx
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let doc = body_json(resp).await;
    assert_eq!(doc["issuer"], fx.origin);
    assert_eq!(
        doc["authorization_endpoint"],
        format!("{}/oauth/authorize", fx.origin)
    );
    assert_eq!(doc["token_endpoint"], format!("{}/oauth/token", fx.origin));
    assert_eq!(
        doc["userinfo_endpoint"],
        format!("{}/oauth/userinfo", fx.origin)
    );
    assert_eq!(
        doc["end_session_endpoint"],
        format!("{}/oauth/end_session", fx.origin)
    );
    assert_eq!(
        doc["jwks_uri"],
        format!("{}/.well-known/jwks.json", fx.origin)
    );
    assert!(
        doc["response_types_supported"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "code")
    );
    assert!(
        doc["id_token_signing_alg_values_supported"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "EdDSA")
    );
    assert!(
        doc["code_challenge_methods_supported"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "S256")
    );
    assert!(
        doc["scopes_supported"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "openid")
    );
}

#[tokio::test]
async fn jwks_exposes_single_ed25519_key() {
    let fx = setup().await;
    let resp = fx
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/jwks.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let keys = body["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    let k = &keys[0];
    assert_eq!(k["kty"], "OKP");
    assert_eq!(k["crv"], "Ed25519");
    assert_eq!(k["alg"], "EdDSA");
    assert_eq!(k["use"], "sig");
    assert_eq!(k["kid"], "test-kid");
    // x should decode to the actual public key bytes.
    let x = k["x"].as_str().unwrap();
    let decoded = URL_SAFE_NO_PAD.decode(x).unwrap();
    assert_eq!(decoded, fx.signing_key.verifying_key().to_bytes().to_vec());
}

// ============================================================================
// Authorization endpoint
// ============================================================================

#[tokio::test]
async fn authorize_redirects_anonymous_to_login() {
    let fx = setup().await;
    let (_, challenge) = make_pkce();
    let url = authorize_url(
        &fx.client_id,
        "https://rp.example.com/cb",
        &challenge,
        "s",
        "n",
    );
    let resp = fx
        .router
        .clone()
        .oneshot(get_with_cookie(&url, None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND);
    let loc = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(
        loc.starts_with("/login?redirect_uri="),
        "unexpected location: {loc}"
    );
}

#[tokio::test]
async fn authorize_issues_code_for_authenticated_user() {
    let fx = setup().await;
    let (_verifier, challenge) = make_pkce();
    let url = authorize_url(
        &fx.client_id,
        "https://rp.example.com/cb",
        &challenge,
        "xyz-state",
        "nonce-value",
    );
    let cookie = issue_session_cookie(&fx);
    let resp = fx
        .router
        .clone()
        .oneshot(get_with_cookie(&url, Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND);
    let loc = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(
        loc.starts_with("https://rp.example.com/cb?code="),
        "loc={loc}"
    );
    assert_eq!(query_param(loc, "state").as_deref(), Some("xyz-state"));
    assert!(query_param(loc, "code").is_some());
}

#[tokio::test]
async fn authorize_rejects_unregistered_redirect_uri() {
    let fx = setup().await;
    let (_, challenge) = make_pkce();
    let url = authorize_url(
        &fx.client_id,
        "https://evil.example.com/cb",
        &challenge,
        "s",
        "n",
    );
    let cookie = issue_session_cookie(&fx);
    let resp = fx
        .router
        .clone()
        .oneshot(get_with_cookie(&url, Some(&cookie)))
        .await
        .unwrap();
    // Never bounce to an unregistered URI.
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_json(resp).await;
    assert_eq!(body["error"], "invalid_request");
}

#[tokio::test]
async fn authorize_bounces_unsupported_response_type_error() {
    let fx = setup().await;
    let (_, challenge) = make_pkce();
    // Manually craft a URL with response_type=token to trigger the error path.
    let url = format!(
        "/oauth/authorize?response_type=token&client_id={}&redirect_uri={}&scope=openid&state=S&nonce=N&code_challenge={}&code_challenge_method=S256",
        urlencoding::encode(&fx.client_id),
        urlencoding::encode("https://rp.example.com/cb"),
        urlencoding::encode(&challenge),
    );
    let cookie = issue_session_cookie(&fx);
    let resp = fx
        .router
        .clone()
        .oneshot(get_with_cookie(&url, Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND);
    let loc = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(loc.starts_with("https://rp.example.com/cb?"), "loc={loc}");
    assert_eq!(
        query_param(loc, "error").as_deref(),
        Some("unsupported_response_type")
    );
    assert_eq!(query_param(loc, "state").as_deref(), Some("S"));
}

#[tokio::test]
async fn authorize_denies_when_role_missing() {
    let fx = setup().await;
    let (_, challenge) = make_pkce();
    let url = authorize_url(
        &fx.gated_client_id,
        "https://gated.example.com/cb",
        &challenge,
        "s",
        "n",
    );
    let cookie = issue_session_cookie(&fx);
    let resp = fx
        .router
        .clone()
        .oneshot(get_with_cookie(&url, Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND);
    let loc = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(loc.starts_with("https://gated.example.com/cb?"));
    assert_eq!(query_param(loc, "error").as_deref(), Some("access_denied"));
    // Avoid unused warning.
    let _ = fx.gated_app_id;
}

#[tokio::test]
async fn authorize_requires_pkce_challenge() {
    let fx = setup().await;
    let url = format!(
        "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid&state=S&nonce=N",
        urlencoding::encode(&fx.client_id),
        urlencoding::encode("https://rp.example.com/cb"),
    );
    let cookie = issue_session_cookie(&fx);
    let resp = fx
        .router
        .clone()
        .oneshot(get_with_cookie(&url, Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND);
    let loc = resp.headers().get("location").unwrap().to_str().unwrap();
    assert_eq!(
        query_param(loc, "error").as_deref(),
        Some("invalid_request")
    );
}

#[tokio::test]
async fn authorize_rejects_scope_without_openid() {
    let fx = setup().await;
    let (_, challenge) = make_pkce();
    let url = format!(
        "/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope=profile&state=S&nonce=N&code_challenge={}&code_challenge_method=S256",
        urlencoding::encode(&fx.client_id),
        urlencoding::encode("https://rp.example.com/cb"),
        urlencoding::encode(&challenge),
    );
    let cookie = issue_session_cookie(&fx);
    let resp = fx
        .router
        .clone()
        .oneshot(get_with_cookie(&url, Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND);
    let loc = resp.headers().get("location").unwrap().to_str().unwrap();
    assert_eq!(query_param(loc, "error").as_deref(), Some("invalid_scope"));
}

#[tokio::test]
async fn authorize_checks_current_roles_instead_of_stale_cookie_roles() {
    let fx = setup().await;
    let (_, challenge) = make_pkce();
    let url = authorize_url(
        &fx.gated_client_id,
        "https://gated.example.com/cb",
        &challenge,
        "s",
        "n",
    );
    let stale =
        generate_access_token(fx.alice_id, vec!["engineer".into()], &fx.signing_key).unwrap();
    let cookie = format!("__Host-authere_token={stale}");
    let response = fx
        .router
        .clone()
        .oneshot(get_with_cookie(&url, Some(&cookie)))
        .await
        .unwrap();
    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(
        query_param(location, "error").as_deref(),
        Some("access_denied")
    );
}

#[tokio::test]
async fn authorize_fails_closed_for_unsupported_reauthentication() {
    let fx = setup().await;
    let (_, challenge) = make_pkce();
    let cookie = issue_session_cookie(&fx);
    for extra in [
        "max_age=0",
        "prompt=login",
        "prompt=consent",
        "prompt=none+login",
        "scope=openid+unknown",
    ] {
        let mut url = authorize_url(
            &fx.client_id,
            "https://rp.example.com/cb",
            &challenge,
            "s",
            "n",
        );
        if extra.starts_with("scope=") {
            url = url.replace("scope=openid+profile+email+roles", extra);
        } else {
            url.push('&');
            url.push_str(extra);
        }
        let response = fx
            .router
            .clone()
            .oneshot(get_with_cookie(&url, Some(&cookie)))
            .await
            .unwrap();
        let location = response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(query_param(location, "code").is_none());
        assert!(query_param(location, "error").is_some());
    }
}

#[tokio::test]
async fn authorize_prompt_none_does_not_redirect_to_login() {
    let fx = setup().await;
    let (_, challenge) = make_pkce();
    let url = format!(
        "{}&prompt=none",
        authorize_url(
            &fx.client_id,
            "https://rp.example.com/cb",
            &challenge,
            "s",
            "n"
        )
    );
    let response = fx
        .router
        .clone()
        .oneshot(get_with_cookie(&url, None))
        .await
        .unwrap();
    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(location.starts_with("https://rp.example.com/cb?"));
    assert_eq!(
        query_param(location, "error").as_deref(),
        Some("login_required")
    );
}

#[tokio::test]
async fn authorize_renews_central_session_without_extending_expiry() {
    let fx = setup().await;
    let mut connection = fx.pool.acquire().await.unwrap();
    authere_server::settings::set_setting("session_expiry_seconds", "300", &mut connection)
        .await
        .unwrap();
    let pair = generate_token_pair(fx.alice_id, vec![], &fx.signing_key, &mut connection)
        .await
        .unwrap();
    drop(connection);
    let payload = URL_SAFE_NO_PAD
        .decode(pair.refresh_token.split('.').nth(1).unwrap())
        .unwrap();
    let parent: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    let (verifier, challenge) = make_pkce();
    let url = format!(
        "{}&prompt=none",
        authorize_url(
            &fx.client_id,
            "https://rp.example.com/cb",
            &challenge,
            "s",
            "n"
        )
    );
    // Browsers drop the short-lived access cookie when it expires, leaving refresh only.
    let cookie = format!("__Host-authere_refresh={}", pair.refresh_token);
    let response = fx
        .router
        .clone()
        .oneshot(get_with_cookie(&url, Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(response.headers().get_all("set-cookie").iter().count(), 2);
    let code = extract_code_from_location(&response);
    let response = fx
        .router
        .clone()
        .oneshot(post_form(
            "/oauth/token",
            &token_form(&fx, &code, &verifier),
            &[],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let tokens = body_json(response).await;
    assert!(tokens["expires_in"].as_i64().unwrap() <= 300);
    let payload = URL_SAFE_NO_PAD
        .decode(
            tokens["id_token"]
                .as_str()
                .unwrap()
                .split('.')
                .nth(1)
                .unwrap(),
        )
        .unwrap();
    let claims: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    assert_eq!(claims["exp"], parent["session_exp"]);
    assert_eq!(claims["auth_time"], parent["auth_time"]);
}

#[tokio::test]
async fn authorize_rejects_malformed_or_implicit_pkce_method() {
    let fx = setup().await;
    let (_, challenge) = make_pkce();
    let valid_url = authorize_url(
        &fx.client_id,
        "https://rp.example.com/cb",
        &challenge,
        "s",
        "n",
    );
    let cookie = issue_session_cookie(&fx);
    for url in [
        valid_url.replace("&code_challenge_method=S256", ""),
        valid_url.replace(&challenge, "invalid"),
    ] {
        let response = fx
            .router
            .clone()
            .oneshot(get_with_cookie(&url, Some(&cookie)))
            .await
            .unwrap();
        let location = response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(
            query_param(location, "error").as_deref(),
            Some("invalid_request")
        );
    }
}

// ============================================================================
// Token endpoint (happy path + error cases)
// ============================================================================

async fn authorize_and_get_code(fx: &Fixture, challenge: &str) -> String {
    let url = authorize_url(
        &fx.client_id,
        "https://rp.example.com/cb",
        challenge,
        "state-x",
        "nonce-x",
    );
    let cookie = issue_session_cookie(fx);
    let resp = fx
        .router
        .clone()
        .oneshot(get_with_cookie(&url, Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND);
    extract_code_from_location(&resp)
}

fn token_form(fx: &Fixture, code: &str, verifier: &str) -> String {
    format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&client_secret={}&code_verifier={}",
        urlencoding::encode(code),
        urlencoding::encode("https://rp.example.com/cb"),
        urlencoding::encode(&fx.client_id),
        urlencoding::encode(&fx.client_secret),
        urlencoding::encode(verifier),
    )
}

async fn token_pair(fx: &Fixture) -> serde_json::Value {
    let (verifier, challenge) = make_pkce();
    let code = authorize_and_get_code(fx, &challenge).await;
    let response = fx
        .router
        .clone()
        .oneshot(post_form(
            "/oauth/token",
            &token_form(fx, &code, &verifier),
            &[],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    body_json(response).await
}

async fn userinfo_request(fx: &Fixture, token: &str) -> Response<Body> {
    fx.router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/oauth/userinfo")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

fn browser_router(fx: &Fixture) -> Router {
    fx.router.clone().layer(middleware::from_fn_with_state(
        BrowserSecurity {
            allowed_origins: vec![fx.origin.clone()],
        },
        protect_browser_requests,
    ))
}

#[tokio::test]
async fn token_exchange_happy_path() {
    let fx = setup().await;
    let (verifier, challenge) = make_pkce();
    let code = authorize_and_get_code(&fx, &challenge).await;

    let body = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&client_secret={}&code_verifier={}",
        urlencoding::encode(&code),
        urlencoding::encode("https://rp.example.com/cb"),
        urlencoding::encode(&fx.client_id),
        urlencoding::encode(&fx.client_secret),
        urlencoding::encode(&verifier),
    );
    let resp = fx
        .router
        .clone()
        .oneshot(post_form("/oauth/token", &body, &[]))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let cc = resp
        .headers()
        .get("cache-control")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(cc, "no-store");

    let body = body_json(resp).await;
    assert_eq!(body["token_type"], "Bearer");
    assert!(body["access_token"].as_str().unwrap().len() > 20);
    assert!(body["id_token"].as_str().unwrap().len() > 20);
    assert!(body["scope"].as_str().unwrap().contains("openid"));

    // Decode the ID token payload (middle segment, base64url no-pad) and check claims.
    let id_token = body["id_token"].as_str().unwrap();
    let parts: Vec<&str> = id_token.split('.').collect();
    assert_eq!(parts.len(), 3);
    let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
    assert_eq!(header["alg"], "EdDSA");
    assert_eq!(header["kid"], "test-kid");
    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
    assert_eq!(payload["iss"], fx.origin);
    assert_eq!(payload["sub"], fx.alice_id.to_string());
    assert_eq!(payload["aud"], fx.client_id);
    assert_eq!(payload["nonce"], "nonce-x");
    assert_eq!(payload["name"], "Alice Example");
    assert_eq!(payload["preferred_username"], "alice");
    assert_eq!(payload["email"], "alice@example.com");
    let _ = fx.app_id;
}

#[tokio::test]
async fn token_rejects_code_replay() {
    let fx = setup().await;
    let (verifier, challenge) = make_pkce();
    let code = authorize_and_get_code(&fx, &challenge).await;
    let form = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&client_secret={}&code_verifier={}",
        urlencoding::encode(&code),
        urlencoding::encode("https://rp.example.com/cb"),
        urlencoding::encode(&fx.client_id),
        urlencoding::encode(&fx.client_secret),
        urlencoding::encode(&verifier),
    );
    let first = fx
        .router
        .clone()
        .oneshot(post_form("/oauth/token", &form, &[]))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);

    let second = fx
        .router
        .clone()
        .oneshot(post_form("/oauth/token", &form, &[]))
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::BAD_REQUEST);
    let body = body_json(second).await;
    assert_eq!(body["error"], "invalid_grant");
}

#[tokio::test]
async fn token_rejects_wrong_pkce_verifier() {
    let fx = setup().await;
    let (_verifier, challenge) = make_pkce();
    let code = authorize_and_get_code(&fx, &challenge).await;
    // Use a valid-format but mismatched verifier.
    let wrong = "A".repeat(43);
    let form = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&client_secret={}&code_verifier={}",
        urlencoding::encode(&code),
        urlencoding::encode("https://rp.example.com/cb"),
        urlencoding::encode(&fx.client_id),
        urlencoding::encode(&fx.client_secret),
        urlencoding::encode(&wrong),
    );
    let resp = fx
        .router
        .clone()
        .oneshot(post_form("/oauth/token", &form, &[]))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(resp).await["error"], "invalid_grant");
}

#[tokio::test]
async fn token_rejects_wrong_client_secret() {
    let fx = setup().await;
    let (verifier, challenge) = make_pkce();
    let code = authorize_and_get_code(&fx, &challenge).await;
    let form = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&client_secret=wrong&code_verifier={}",
        urlencoding::encode(&code),
        urlencoding::encode("https://rp.example.com/cb"),
        urlencoding::encode(&fx.client_id),
        urlencoding::encode(&verifier),
    );
    let resp = fx
        .router
        .clone()
        .oneshot(post_form("/oauth/token", &form, &[]))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body_json(resp).await["error"], "invalid_client");
}

#[tokio::test]
async fn token_rejects_redirect_uri_mismatch() {
    let fx = setup().await;
    let (verifier, challenge) = make_pkce();
    let code = authorize_and_get_code(&fx, &challenge).await;
    let form = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&client_secret={}&code_verifier={}",
        urlencoding::encode(&code),
        // Different redirect_uri than authorize used — must be rejected.
        urlencoding::encode("https://rp.example.com/other"),
        urlencoding::encode(&fx.client_id),
        urlencoding::encode(&fx.client_secret),
        urlencoding::encode(&verifier),
    );
    let resp = fx
        .router
        .clone()
        .oneshot(post_form("/oauth/token", &form, &[]))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(resp).await["error"], "invalid_grant");
}

#[tokio::test]
async fn token_rejects_code_issued_to_different_client() {
    let fx = setup().await;
    let (verifier, challenge) = make_pkce();
    let code = authorize_and_get_code(&fx, &challenge).await;
    // Present code A via client B — must fail.
    let form = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&code_verifier={}",
        urlencoding::encode(&code),
        urlencoding::encode("https://rp.example.com/cb"),
        urlencoding::encode(&fx.public_client_id),
        urlencoding::encode(&verifier),
    );
    let resp = fx
        .router
        .clone()
        .oneshot(post_form("/oauth/token", &form, &[]))
        .await
        .unwrap();
    // Public client has no secret, so client-auth passes but the code is bound to a
    // different application — expect invalid_grant.
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let _ = fx.public_app_id;
    assert_eq!(body_json(resp).await["error"], "invalid_grant");
}

#[tokio::test]
async fn token_supports_http_basic_client_auth() {
    let fx = setup().await;
    let (verifier, challenge) = make_pkce();
    let code = authorize_and_get_code(&fx, &challenge).await;
    let basic = B64.encode(format!("{}:{}", fx.client_id, fx.client_secret));
    let header = format!("Basic {basic}");
    let form = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&code_verifier={}",
        urlencoding::encode(&code),
        urlencoding::encode("https://rp.example.com/cb"),
        urlencoding::encode(&verifier),
    );
    let resp = fx
        .router
        .clone()
        .oneshot(post_form(
            "/oauth/token",
            &form,
            &[("authorization", &header)],
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn token_public_client_succeeds_without_secret() {
    let fx = setup().await;
    let (verifier, challenge) = make_pkce();
    // Authorize using the public client.
    let url = authorize_url(
        &fx.public_client_id,
        "https://spa.example.com/cb",
        &challenge,
        "s",
        "n",
    );
    let cookie = issue_session_cookie(&fx);
    let authz = fx
        .router
        .clone()
        .oneshot(get_with_cookie(&url, Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(authz.status(), StatusCode::FOUND);
    let code = extract_code_from_location(&authz);

    let form = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&code_verifier={}",
        urlencoding::encode(&code),
        urlencoding::encode("https://spa.example.com/cb"),
        urlencoding::encode(&fx.public_client_id),
        urlencoding::encode(&verifier),
    );
    let resp = fx
        .router
        .clone()
        .oneshot(post_form("/oauth/token", &form, &[]))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert!(body["access_token"].as_str().unwrap().len() > 20);
}

#[tokio::test]
async fn token_rejects_unsupported_grant_type() {
    let fx = setup().await;
    let form = format!(
        "grant_type=client_credentials&client_id={}&client_secret={}",
        urlencoding::encode(&fx.client_id),
        urlencoding::encode(&fx.client_secret),
    );
    let resp = fx
        .router
        .clone()
        .oneshot(post_form("/oauth/token", &form, &[]))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(resp).await["error"], "unsupported_grant_type");
}

#[tokio::test]
async fn token_rechecks_role_gates_before_exchange() {
    let fx = setup().await;
    let (verifier, challenge) = make_pkce();
    let code = authorize_and_get_code(&fx, &challenge).await;
    sqlx::query("UPDATE applications SET required_roles = ? WHERE id = ?")
        .bind("[\"engineer\"]")
        .bind(fx.app_id)
        .execute(&fx.pool)
        .await
        .unwrap();
    let response = fx
        .router
        .clone()
        .oneshot(post_form(
            "/oauth/token",
            &token_form(&fx, &code, &verifier),
            &[],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["error"], "invalid_grant");
}

#[tokio::test]
async fn token_rejects_code_after_parent_session_revocation() {
    let fx = setup().await;
    let (verifier, challenge) = make_pkce();
    let code = authorize_and_get_code(&fx, &challenge).await;
    let mut connection = fx.pool.acquire().await.unwrap();
    revoke_all_user_tokens(fx.alice_id, &mut connection)
        .await
        .unwrap();
    drop(connection);
    let response = fx
        .router
        .clone()
        .oneshot(post_form(
            "/oauth/token",
            &token_form(&fx, &code, &verifier),
            &[],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["error"], "invalid_grant");
}

#[tokio::test]
async fn token_rejects_conflicting_or_malformed_client_authentication() {
    let fx = setup().await;
    let (verifier, challenge) = make_pkce();
    let code = authorize_and_get_code(&fx, &challenge).await;
    let form = token_form(&fx, &code, &verifier);
    let basic = format!(
        "Basic {}",
        B64.encode(format!("{}:{}", fx.client_id, fx.client_secret))
    );
    let malformed = fx
        .router
        .clone()
        .oneshot(post_form(
            "/oauth/token",
            &form,
            &[("authorization", "Basic invalid")],
        ))
        .await
        .unwrap();
    assert_eq!(malformed.status(), StatusCode::UNAUTHORIZED);
    let conflict = fx
        .router
        .clone()
        .oneshot(post_form(
            "/oauth/token",
            &form,
            &[("authorization", &basic)],
        ))
        .await
        .unwrap();
    assert_eq!(conflict.status(), StatusCode::BAD_REQUEST);
    let correct = fx
        .router
        .clone()
        .oneshot(post_form("/oauth/token", &form, &[]))
        .await
        .unwrap();
    assert_eq!(correct.status(), StatusCode::OK);
}

// ============================================================================
// UserInfo
// ============================================================================

#[tokio::test]
async fn userinfo_returns_scope_gated_claims() {
    let fx = setup().await;
    let (verifier, challenge) = make_pkce();
    let code = authorize_and_get_code(&fx, &challenge).await;
    let form = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&client_secret={}&code_verifier={}",
        urlencoding::encode(&code),
        urlencoding::encode("https://rp.example.com/cb"),
        urlencoding::encode(&fx.client_id),
        urlencoding::encode(&fx.client_secret),
        urlencoding::encode(&verifier),
    );
    let token_resp = fx
        .router
        .clone()
        .oneshot(post_form("/oauth/token", &form, &[]))
        .await
        .unwrap();
    let body = body_json(token_resp).await;
    let access_token = body["access_token"].as_str().unwrap().to_string();

    let resp = fx
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/oauth/userinfo")
                .header("authorization", format!("Bearer {access_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["sub"], fx.alice_id.to_string());
    assert_eq!(body["preferred_username"], "alice");
    assert_eq!(body["name"], "Alice Example");
    assert_eq!(body["email"], "alice@example.com");
    // roles scope was requested, so roles array is present (may be empty for Alice).
    assert!(body.get("roles").is_some());
}

#[tokio::test]
async fn userinfo_rejects_missing_bearer() {
    let fx = setup().await;
    let resp = fx
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/oauth/userinfo")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let www = resp
        .headers()
        .get("www-authenticate")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(www.contains("Bearer"));
}

#[tokio::test]
async fn userinfo_rejects_internal_access_token() {
    let fx = setup().await;
    // A regular Authere access token (typ=access) must not be usable at /userinfo.
    let token = generate_access_token(fx.alice_id, vec![], &fx.signing_key).unwrap();
    let resp = fx
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/oauth/userinfo")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn userinfo_rejects_disabled_clients_and_revoked_access() {
    for change in ["disabled", "roles", "session"] {
        let fx = setup().await;
        let tokens = token_pair(&fx).await;
        let token = tokens["access_token"].as_str().unwrap();
        assert_eq!(userinfo_request(&fx, token).await.status(), StatusCode::OK);
        match change {
            "disabled" => {
                sqlx::query("UPDATE applications SET enabled = 0 WHERE id = ?")
                    .bind(fx.app_id)
                    .execute(&fx.pool)
                    .await
                    .unwrap();
            }
            "roles" => {
                sqlx::query("UPDATE applications SET required_roles = ? WHERE id = ?")
                    .bind("[\"engineer\"]")
                    .bind(fx.app_id)
                    .execute(&fx.pool)
                    .await
                    .unwrap();
            }
            _ => {
                let mut connection = fx.pool.acquire().await.unwrap();
                revoke_all_user_tokens(fx.alice_id, &mut connection)
                    .await
                    .unwrap();
            }
        }
        assert_eq!(
            userinfo_request(&fx, token).await.status(),
            StatusCode::UNAUTHORIZED,
            "change={change}"
        );
    }
}

// ============================================================================
// RP-initiated logout
// ============================================================================

#[tokio::test]
async fn end_session_redirects_to_allowed_post_logout_uri() {
    let fx = setup().await;
    let cookie = issue_session_cookie(&fx);
    let tokens = token_pair(&fx).await;
    let url = format!(
        "/oauth/end_session?client_id={}&post_logout_redirect_uri={}&state=abc&id_token_hint={}",
        urlencoding::encode(&fx.client_id),
        urlencoding::encode("https://rp.example.com/logged-out"),
        urlencoding::encode(tokens["id_token"].as_str().unwrap()),
    );
    let resp = fx
        .router
        .clone()
        .oneshot(get_with_cookie(&url, Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND);
    let loc = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(loc.starts_with("https://rp.example.com/logged-out"));
    assert_eq!(query_param(loc, "state").as_deref(), Some("abc"));
    // Cookie should be cleared.
    let set_cookie = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|h| h.to_str().unwrap().to_string())
        .collect::<Vec<_>>();
    assert!(
        set_cookie
            .iter()
            .any(|c| c.contains("__Host-authere_token=") && c.contains("Max-Age=0"))
    );
    // Keep the pool around so it's not dropped mid-test.
    let _ = fx.pool;
}

#[tokio::test]
async fn end_session_refuses_unregistered_post_logout_uri() {
    let fx = setup().await;
    let cookie = issue_session_cookie(&fx);
    let form = format!(
        "client_id={}&post_logout_redirect_uri={}",
        urlencoding::encode(&fx.client_id),
        urlencoding::encode("https://evil.example.com/landing"),
    );
    let resp = fx
        .router
        .clone()
        .oneshot(post_form(
            "/oauth/end_session",
            &form,
            &[("cookie", &cookie), ("origin", &fx.origin)],
        ))
        .await
        .unwrap();
    // Falls back to the default signed-out landing (200) rather than redirecting anywhere
    // untrusted.
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "text/html; charset=utf-8",
    );
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8(body.to_vec()).unwrap();
    assert!(body.contains("<title>Signed out</title>"));
    assert!(body.contains("You're signed out"));
    assert!(body.contains(&format!("href=\"{}/login\"", fx.origin)));
}

#[tokio::test]
async fn end_session_requires_user_confirmation_without_a_matching_hint() {
    let fx = setup().await;
    let cookie = issue_session_cookie(&fx);
    let response = fx
        .router
        .clone()
        .oneshot(get_with_cookie("/oauth/end_session", Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get("set-cookie").is_none());
    assert!(
        String::from_utf8(body_bytes(response).await)
            .unwrap()
            .contains("Sign out of Authere?")
    );

    // A cross-site form cannot approve that confirmation on the user's behalf.
    let response = fx
        .router
        .clone()
        .oneshot(post_form(
            "/oauth/end_session",
            "",
            &[("cookie", &cookie), ("origin", "https://outside.example")],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(response.headers().get("set-cookie").is_none());
    let mut connection = fx.pool.acquire().await.unwrap();
    let token = cookie.strip_prefix("__Host-authere_token=").unwrap();
    assert!(
        verify_access_token(token, &fx.signing_key, &mut connection)
            .await
            .is_ok()
    );
    drop(connection);

    let response = fx
        .router
        .clone()
        .oneshot(post_form(
            "/oauth/end_session",
            "",
            &[("cookie", &cookie), ("origin", &fx.origin)],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get("set-cookie").is_some());
    let mut connection = fx.pool.acquire().await.unwrap();
    assert!(
        verify_access_token(token, &fx.signing_key, &mut connection)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn end_session_with_refresh_only_confirms_and_revokes_the_session() {
    let fx = setup().await;
    let tokens = token_pair(&fx).await;
    let mut connection = fx.pool.acquire().await.unwrap();
    let pair = generate_token_pair(fx.alice_id, vec![], &fx.signing_key, &mut connection)
        .await
        .unwrap();
    drop(connection);
    let cookie = format!("__Host-authere_refresh={}", pair.refresh_token);
    let response = fx
        .router
        .clone()
        .oneshot(get_with_cookie("/oauth/end_session", Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let renewed = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|value| {
            value
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .to_string()
        })
        .collect::<Vec<_>>()
        .join("; ");
    assert!(renewed.contains("__Host-authere_refresh="));
    assert!(
        String::from_utf8(body_bytes(response).await)
            .unwrap()
            .contains("Sign out of Authere?")
    );
    assert_eq!(
        userinfo_request(&fx, tokens["access_token"].as_str().unwrap())
            .await
            .status(),
        StatusCode::OK
    );
    let response = fx
        .router
        .clone()
        .oneshot(post_form(
            "/oauth/end_session",
            "",
            &[("cookie", &renewed), ("origin", &fx.origin)],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .get_all("set-cookie")
            .iter()
            .all(|value| value.to_str().unwrap().contains("Max-Age=0"))
    );
    assert_eq!(
        userinfo_request(&fx, tokens["access_token"].as_str().unwrap())
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn end_session_hint_without_browser_session_cannot_revoke_user_tokens() {
    let fx = setup().await;
    let tokens = token_pair(&fx).await;
    let url = format!(
        "/oauth/end_session?id_token_hint={}",
        urlencoding::encode(tokens["id_token"].as_str().unwrap())
    );
    let response = fx
        .router
        .clone()
        .oneshot(get_with_cookie(&url, None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        userinfo_request(&fx, tokens["access_token"].as_str().unwrap())
            .await
            .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn end_session_rejects_access_token_hints_and_client_mismatch() {
    let fx = setup().await;
    let tokens = token_pair(&fx).await;
    let cookie = issue_session_cookie(&fx);
    for url in [
        format!(
            "/oauth/end_session?id_token_hint={}",
            urlencoding::encode(tokens["access_token"].as_str().unwrap())
        ),
        format!(
            "/oauth/end_session?client_id={}&id_token_hint={}",
            urlencoding::encode(&fx.public_client_id),
            urlencoding::encode(tokens["id_token"].as_str().unwrap())
        ),
    ] {
        let response = fx
            .router
            .clone()
            .oneshot(get_with_cookie(&url, Some(&cookie)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(response.headers().get("set-cookie").is_none());
    }
    assert_eq!(
        userinfo_request(&fx, tokens["access_token"].as_str().unwrap())
            .await
            .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn end_session_does_not_revoke_a_different_hinted_user() {
    let fx = setup().await;
    let tokens = token_pair(&fx).await;
    let bob = User::new("bob".into(), "Bob".into(), None);
    let mut connection = fx.pool.acquire().await.unwrap();
    bob.save(&mut connection).await.unwrap();
    drop(connection);
    let bob_token = generate_access_token(bob.id, vec![], &fx.signing_key).unwrap();
    let cookie = format!("__Host-authere_token={bob_token}");
    let url = format!(
        "/oauth/end_session?id_token_hint={}",
        urlencoding::encode(tokens["id_token"].as_str().unwrap())
    );
    let response = fx
        .router
        .clone()
        .oneshot(get_with_cookie(&url, Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get("set-cookie").is_none());
    assert!(
        String::from_utf8(body_bytes(response).await)
            .unwrap()
            .contains("Sign out of Authere?")
    );
    assert_eq!(
        userinfo_request(&fx, tokens["access_token"].as_str().unwrap())
            .await
            .status(),
        StatusCode::OK
    );
    let mut connection = fx.pool.acquire().await.unwrap();
    assert!(
        verify_access_token(&bob_token, &fx.signing_key, &mut connection)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn end_session_accepts_expired_matching_id_token_hint_and_resolves_client() {
    let fx = setup().await;
    let tokens = token_pair(&fx).await;
    let jwt = tokens["id_token"].as_str().unwrap();
    let payload = URL_SAFE_NO_PAD
        .decode(jwt.split('.').nth(1).unwrap())
        .unwrap();
    let mut claims: authere_server::oidc::token::IdTokenClaims =
        serde_json::from_slice(&payload).unwrap();
    claims.exp = claims.iat - 1;
    let expired_hint =
        authere_server::oidc::token::encode_id_token(&claims, &fx.signing_key, "test-kid").unwrap();
    let cookie = issue_session_cookie(&fx);
    let url = format!(
        "/oauth/end_session?id_token_hint={}&post_logout_redirect_uri={}",
        urlencoding::encode(&expired_hint),
        urlencoding::encode("https://rp.example.com/logged-out")
    );
    let response = fx
        .router
        .clone()
        .oneshot(get_with_cookie(&url, Some(&cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response.headers().get("location").unwrap(),
        "https://rp.example.com/logged-out"
    );
    assert_eq!(
        userinfo_request(&fx, tokens["access_token"].as_str().unwrap())
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn rp_post_end_session_with_matching_hint_succeeds_through_origin_guard() {
    let fx = setup().await;
    let tokens = token_pair(&fx).await;
    let cookie = issue_session_cookie(&fx);
    let form = format!(
        "client_id={}&id_token_hint={}&post_logout_redirect_uri={}",
        urlencoding::encode(&fx.client_id),
        urlencoding::encode(tokens["id_token"].as_str().unwrap()),
        urlencoding::encode("https://rp.example.com/logged-out")
    );
    let response = browser_router(&fx)
        .oneshot(post_form(
            "/oauth/end_session",
            &form,
            &[
                ("cookie", &cookie),
                ("origin", "https://rp.example.com"),
                ("sec-fetch-site", "same-site"),
            ],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response.headers()["location"],
        "https://rp.example.com/logged-out"
    );
    assert_eq!(response.headers().get_all("set-cookie").iter().count(), 2);
    assert!(
        response
            .headers()
            .get_all("set-cookie")
            .iter()
            .all(|value| value.to_str().unwrap().contains("Max-Age=0"))
    );
    assert_eq!(
        userinfo_request(&fx, tokens["access_token"].as_str().unwrap())
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn untrusted_logout_posts_cannot_clear_cookies_or_renew_browser_sessions() {
    let fx = setup().await;
    let tokens = token_pair(&fx).await;
    let cookie = issue_session_cookie(&fx);
    let mut connection = fx.pool.acquire().await.unwrap();
    let pair = generate_token_pair(fx.alice_id, vec![], &fx.signing_key, &mut connection)
        .await
        .unwrap();
    let bob = User::new("bob-rp-post".into(), "Bob".into(), None);
    bob.save(&mut connection).await.unwrap();
    drop(connection);
    let refresh_only = format!("__Host-authere_refresh={}", pair.refresh_token);
    let bob_cookie = format!(
        "__Host-authere_token={}",
        generate_access_token(bob.id, vec![], &fx.signing_key).unwrap()
    );
    let valid_hint = format!(
        "id_token_hint={}",
        urlencoding::encode(tokens["id_token"].as_str().unwrap())
    );
    let access_hint = format!(
        "id_token_hint={}",
        urlencoding::encode(tokens["access_token"].as_str().unwrap())
    );
    let wrong_client = format!(
        "{valid_hint}&client_id={}",
        urlencoding::encode(&fx.public_client_id)
    );
    for (form, browser_cookie) in [
        ("", ""),
        (valid_hint.as_str(), ""),
        ("", cookie.as_str()),
        ("id_token_hint=invalid", cookie.as_str()),
        (access_hint.as_str(), cookie.as_str()),
        (wrong_client.as_str(), cookie.as_str()),
        (valid_hint.as_str(), refresh_only.as_str()),
        (valid_hint.as_str(), bob_cookie.as_str()),
    ] {
        let response = browser_router(&fx)
            .oneshot(post_form(
                "/oauth/end_session",
                form,
                &[
                    ("cookie", browser_cookie),
                    ("origin", "https://outside.invalid"),
                    ("sec-fetch-site", "cross-site"),
                ],
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(response.headers().get("set-cookie").is_none());
    }
    assert_eq!(
        userinfo_request(&fx, tokens["access_token"].as_str().unwrap())
            .await
            .status(),
        StatusCode::OK
    );
    let revoked: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM refresh_tokens WHERE revoked_at IS NOT NULL")
            .fetch_one(&fx.pool)
            .await
            .unwrap();
    assert_eq!(
        revoked, 0,
        "untrusted requests must not consume refresh tokens"
    );
}

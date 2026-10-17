//! End-to-end checks for the trust boundary between Authere and protected sites.
use authere_server::{
    AppState,
    application::{Application, CreateApplicationInput},
    db::DbEntity,
    handlers::auth,
    rate_limit::{RateLimitConfig, RateLimiter},
    user::{
        User,
        auth::{forward, token},
    },
};
use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode},
    routing::get,
};
use ed25519_dalek::SigningKey;
use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};
use std::sync::Arc;
use tower::ServiceExt;

struct Fixture {
    router: Router,
    pool: SqlitePool,
    user: User,
    pair: token::TokenPair,
    key: Arc<SigningKey>,
}

async fn fixture() -> Fixture {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::migrate!("../migrations").run(&pool).await.unwrap();
    let key = Arc::new(SigningKey::generate(&mut rand::rngs::OsRng));
    let mut conn = pool.acquire().await.unwrap();
    let user = User {
        id: uuid::Uuid::new_v4(),
        username: "alice".into(),
        name: "Alice".into(),
        email: Some("alice@example.com".into()),
        active: true,
        created_at: 0,
        updated_at: 0,
    };
    user.save(&mut conn).await.unwrap();
    sqlx::query(
        "INSERT INTO user_roles (user_id, role_id) SELECT ?, id FROM roles WHERE name = 'user'",
    )
    .bind(user.id)
    .execute(&mut *conn)
    .await
    .unwrap();
    application("app", "app.example.com", None, vec!["user".into()], true)
        .save(&mut conn)
        .await
        .unwrap();
    let pair = token::generate_token_pair(user.id, vec!["user".into()], &key, &mut conn)
        .await
        .unwrap();
    drop(conn);
    let limiter = || RateLimiter::new(RateLimitConfig::default());
    let state = AppState {
        db_pool: pool.clone(),
        login_rate_limiter: limiter(),
        register_rate_limiter: limiter(),
        ldap_bind_rate_limiter: limiter(),
        oidc_token_rate_limiter: limiter(),
        signing_key: key.clone(),
        signing_kid: "test".into(),
        origin: "https://auth.example.com".into(),
        shutdown: Arc::new(tokio::sync::Notify::new()),
    };
    let router = Router::new()
        .route("/api/auth/verify", get(auth::verify_auth))
        .route("/.authere/start", get(auth::forward_auth_start))
        .route("/api/auth/forward-redirect", get(auth::forward_redirect))
        .route("/.authere/callback", get(auth::forward_auth_callback))
        .with_state(state);
    Fixture {
        router,
        pool,
        user,
        pair,
        key,
    }
}

fn application(
    slug: &str,
    host: &str,
    path: Option<&str>,
    roles: Vec<String>,
    enabled: bool,
) -> Application {
    Application::new(CreateApplicationInput {
        name: slug.into(),
        slug: slug.into(),
        app_type: None,
        host_pattern: Some(host.into()),
        path_prefix: path.map(Into::into),
        required_roles: Some(roles),
        enabled: Some(enabled),
        oidc_redirect_uris: None,
        oidc_post_logout_redirect_uris: None,
        oidc_confidential: None,
    })
}

fn request(uri: &str, host: &str, cookie: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder().uri(uri).header("host", host);
    if let Some(cookie) = cookie {
        builder = builder.header("cookie", cookie);
    }
    builder.body(Body::empty()).unwrap()
}

fn location(headers: &HeaderMap) -> &str {
    headers.get("location").unwrap().to_str().unwrap()
}
fn path(url: &str) -> String {
    let url = url::Url::parse(url).unwrap();
    url[url::Position::BeforePath..].to_string()
}
fn cookie(headers: &HeaderMap, name: &str) -> String {
    headers
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap())
        .find(|value| value.starts_with(&format!("{name}=")))
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

async fn handoff(f: &Fixture, target_path: &str) -> (String, String) {
    let start = f
        .router
        .clone()
        .oneshot(request(
            &format!(
                "/.authere/start?redirect_uri={}",
                urlencoding::encode(target_path)
            ),
            "app.example.com",
            None,
        ))
        .await
        .unwrap();
    assert_eq!(start.status(), StatusCode::SEE_OTHER);
    let nonce = cookie(start.headers(), forward::STATE_COOKIE);
    let transfer = f
        .router
        .clone()
        .oneshot(request(
            &path(location(start.headers())),
            "auth.example.com",
            Some(&format!("__Host-authere_token={}", f.pair.access_token)),
        ))
        .await
        .unwrap();
    assert_eq!(transfer.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        transfer.headers().get("referrer-policy").unwrap(),
        "no-referrer"
    );
    (path(location(transfer.headers())), nonce)
}

async fn app_session(f: &Fixture) -> String {
    let (callback, nonce) = handoff(f, "/dashboard?view=recent").await;
    let response = f
        .router
        .clone()
        .oneshot(request(&callback, "app.example.com", Some(&nonce)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(response.headers()), "/dashboard?view=recent");
    // Only host-scoped session credentials are created; legacy global cookies are cleared.
    for value in response.headers().get_all("set-cookie").iter() {
        let value = value.to_str().unwrap();
        if value.starts_with("authere_token=")
            || value.starts_with("authere_refresh=")
            || value.starts_with("__Host-authere_token=")
            || value.starts_with("__Host-authere_refresh=")
        {
            assert!(value.contains("Max-Age=0"));
        }
    }
    cookie(response.headers(), forward::SESSION_COOKIE)
}

async fn verify(f: &Fixture, host: &str, uri: &str, session: &str) -> axum::response::Response {
    let mut request = request("/api/auth/verify", "auth.example.com", Some(session));
    request
        .headers_mut()
        .insert("x-forwarded-host", host.parse().unwrap());
    request
        .headers_mut()
        .insert("x-forwarded-proto", "https".parse().unwrap());
    request
        .headers_mut()
        .insert("x-forwarded-uri", uri.parse().unwrap());
    f.router.clone().oneshot(request).await.unwrap()
}

#[tokio::test]
async fn successful_forward_login_preserves_query_and_returns_current_identity() {
    let f = fixture().await;
    let session = app_session(&f).await;
    let response = verify(&f, "app.example.com", "/dashboard?view=recent", &session).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers().get("x-auth-username").unwrap(), "alice");
    assert_eq!(response.headers().get("x-auth-roles").unwrap(), "user");
    assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
}

#[tokio::test]
async fn unknown_disabled_and_lookalike_hosts_fail_closed() {
    let f = fixture().await;
    let session = app_session(&f).await;
    for host in ["unknown.example.com", "appXexample.com"] {
        assert_eq!(
            verify(&f, host, "/", &session).await.status(),
            StatusCode::FORBIDDEN
        );
    }
    sqlx::query("UPDATE applications SET enabled = 0")
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        verify(&f, "app.example.com", "/", &session).await.status(),
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn global_api_credentials_and_other_origin_sessions_are_rejected() {
    let f = fixture().await;
    let global = format!("__Host-authere_token={}", f.pair.access_token);
    assert_eq!(
        verify(&f, "app.example.com", "/", &global).await.status(),
        StatusCode::SEE_OTHER
    );
    let session = app_session(&f).await;
    let mut conn = f.pool.acquire().await.unwrap();
    application("other", "other.example.com", None, vec![], true)
        .save(&mut conn)
        .await
        .unwrap();
    drop(conn);
    assert_eq!(
        verify(&f, "other.example.com", "/", &session)
            .await
            .status(),
        StatusCode::SEE_OTHER
    );
}

#[tokio::test]
async fn revocation_and_role_removal_take_effect_for_existing_app_sessions() {
    let f = fixture().await;
    let session = app_session(&f).await;
    sqlx::query("DELETE FROM user_roles WHERE user_id = ?")
        .bind(f.user.id)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        verify(&f, "app.example.com", "/", &session).await.status(),
        StatusCode::FORBIDDEN
    );
    let mut conn = f.pool.acquire().await.unwrap();
    token::revoke_all_user_tokens(f.user.id, &mut conn)
        .await
        .unwrap();
    drop(conn);
    assert_eq!(
        verify(&f, "app.example.com", "/", &session).await.status(),
        StatusCode::SEE_OTHER
    );
}

#[tokio::test]
async fn callback_requires_browser_state_and_can_only_be_redeemed_once() {
    let f = fixture().await;
    let (callback, nonce) = handoff(&f, "/dashboard").await;
    for bad_cookie in [None, Some("__Host-authere_forward_state=incorrect")] {
        let response = f
            .router
            .clone()
            .oneshot(request(&callback, "app.example.com", bad_cookie))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    let response = f
        .router
        .clone()
        .oneshot(request(&callback, "app.example.com", Some(&nonce)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let replay = f
        .router
        .clone()
        .oneshot(request(&callback, "app.example.com", Some(&nonce)))
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn handoffs_reject_unknown_or_insecure_targets_and_signed_path_cannot_be_overridden() {
    let f = fixture().await;
    for (target, expected) in [
        ("https://outsider.example/", StatusCode::FORBIDDEN),
        ("http://app.example.com/", StatusCode::BAD_REQUEST),
        (
            "https://app.example.com@outsider.example/",
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let url = format!(
            "/api/auth/forward-redirect?redirect_uri={}&state={}",
            urlencoding::encode(target),
            "a".repeat(64)
        );
        let response = f
            .router
            .clone()
            .oneshot(request(
                &url,
                "auth.example.com",
                Some(&format!("__Host-authere_token={}", f.pair.access_token)),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
    let (callback, nonce) = handoff(&f, "/dashboard?x=1").await;
    let response = f
        .router
        .clone()
        .oneshot(request(
            &format!("{callback}&redirect_uri=%2F%2Fevil.example"),
            "app.example.com",
            Some(&nonce),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(response.headers()), "/dashboard?x=1");
}

#[tokio::test]
async fn path_specific_policies_override_broader_apps_including_encoded_paths() {
    let f = fixture().await;
    let session = app_session(&f).await;
    let mut conn = f.pool.acquire().await.unwrap();
    application(
        "restricted",
        "app.example.com",
        Some("/private"),
        vec!["admin".into()],
        true,
    )
    .save(&mut conn)
    .await
    .unwrap();
    drop(conn);
    for path in [
        "/private",
        "/%70rivate",
        "/public/..%2fprivate",
        "/public/%252e%252e/private",
    ] {
        assert_eq!(
            verify(&f, "app.example.com", path, &session).await.status(),
            StatusCode::FORBIDDEN,
            "{path}"
        );
    }
    sqlx::query("UPDATE applications SET enabled = 0 WHERE slug = 'restricted'")
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        verify(&f, "app.example.com", "/private", &session)
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn overlapping_equal_policies_fail_closed_and_proxy_metadata_is_required() {
    let f = fixture().await;
    let session = app_session(&f).await;
    let response = f
        .router
        .clone()
        .oneshot(request(
            "/api/auth/verify",
            "app.example.com",
            Some(&session),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let mut conn = f.pool.acquire().await.unwrap();
    application("ambiguous", "app.example.com", None, vec![], true)
        .save(&mut conn)
        .await
        .unwrap();
    drop(conn);
    assert_eq!(
        verify(&f, "app.example.com", "/", &session).await.status(),
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn app_credentials_cannot_authenticate_to_authere_or_refresh_global_sessions() {
    let f = fixture().await;
    let session = app_session(&f).await;
    let token_string = session.split_once('=').unwrap().1;
    let mut conn = f.pool.acquire().await.unwrap();
    assert!(matches!(
        token::verify_access_token(token_string, &f.key, &mut conn).await,
        Err(authere_server::errors::AppError::AuthenticationRequired)
    ));
    assert!(matches!(
        token::verify_and_revoke_refresh_token(token_string, &f.key, &mut conn).await,
        Err(authere_server::errors::AppError::AuthenticationRequired)
    ));
}

#[tokio::test]
async fn parent_expiry_and_revocation_apply_to_handoffs_and_app_sessions() {
    let f = fixture().await;
    let state = forward::new_state();
    let mut conn = f.pool.acquire().await.unwrap();
    let mut claims = token::verify_access_token(&f.pair.access_token, &f.key, &mut conn)
        .await
        .unwrap();
    claims.session_exp = Some(forward::now() + 75);
    let application_id = uuid::Uuid::new_v4();
    let handoff = forward::issue_handoff(
        &claims,
        application_id,
        "https://app.example.com",
        "/",
        &state,
        &f.key,
        &mut conn,
    )
    .await
    .unwrap();
    let (session, scoped, _) = forward::redeem_handoff(
        &handoff,
        "https://app.example.com",
        &state,
        &f.key,
        &mut conn,
    )
    .await
    .unwrap();
    assert_eq!(scoped.exp, claims.session_exp.unwrap());
    assert_eq!(scoped.iat, claims.iat);
    assert_eq!(scoped.session_version, claims.session_version);
    assert!(
        forward::verify_session(&session, "https://app.example.com:444", &f.key, &mut conn)
            .await
            .is_err()
    );
    let pending = forward::issue_handoff(
        &claims,
        application_id,
        "https://app.example.com",
        "/",
        &state,
        &f.key,
        &mut conn,
    )
    .await
    .unwrap();
    token::revoke_all_user_tokens(f.user.id, &mut conn)
        .await
        .unwrap();
    assert!(
        forward::redeem_handoff(
            &pending,
            "https://app.example.com",
            &state,
            &f.key,
            &mut conn
        )
        .await
        .is_err()
    );
    assert!(
        forward::verify_session(&session, "https://app.example.com", &f.key, &mut conn)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn duplicate_auth_cookies_and_forwarding_headers_are_rejected() {
    let f = fixture().await;
    let session = app_session(&f).await;
    let duplicated = format!("{session}; {session}");
    assert_eq!(
        verify(&f, "app.example.com", "/", &duplicated)
            .await
            .status(),
        StatusCode::SEE_OTHER
    );
    let mut req = request("/api/auth/verify", "auth.example.com", Some(&session));
    req.headers_mut()
        .append("x-forwarded-host", "app.example.com".parse().unwrap());
    req.headers_mut()
        .append("x-forwarded-host", "other.example.com".parse().unwrap());
    req.headers_mut()
        .append("x-forwarded-uri", "/".parse().unwrap());
    let response = f.router.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn callback_proxy_can_preserve_target_without_changing_upstream_host() {
    let f = fixture().await;
    let mut start_request = request(
        "/.authere/start?redirect_uri=%2Fdashboard%3Ftab%3D1",
        "auth.example.com",
        None,
    );
    start_request
        .headers_mut()
        .insert("x-authere-target-host", "app.example.com".parse().unwrap());
    let start = f.router.clone().oneshot(start_request).await.unwrap();
    assert_eq!(start.status(), StatusCode::SEE_OTHER);
    let nonce = cookie(start.headers(), forward::STATE_COOKIE);
    let transfer = f
        .router
        .clone()
        .oneshot(request(
            &path(location(start.headers())),
            "auth.example.com",
            Some(&format!("__Host-authere_token={}", f.pair.access_token)),
        ))
        .await
        .unwrap();
    assert_eq!(transfer.status(), StatusCode::SEE_OTHER);
    let mut callback = request(
        &path(location(transfer.headers())),
        "auth.example.com",
        Some(&nonce),
    );
    callback
        .headers_mut()
        .insert("x-authere-target-host", "app.example.com".parse().unwrap());
    let response = f.router.clone().oneshot(callback).await.unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(response.headers()), "/dashboard?tab=1");
    let session = cookie(response.headers(), forward::SESSION_COOKIE);
    // The handoff routing hint cannot select another application for verification.
    let mut verify_request = request("/api/auth/verify", "auth.example.com", Some(&session));
    verify_request
        .headers_mut()
        .insert("x-forwarded-host", "outsider.example".parse().unwrap());
    verify_request
        .headers_mut()
        .insert("x-forwarded-uri", "/".parse().unwrap());
    verify_request
        .headers_mut()
        .insert("x-authere-target-host", "app.example.com".parse().unwrap());
    assert_eq!(
        f.router
            .clone()
            .oneshot(verify_request)
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn target_authority_keeps_explicit_ports_and_normalizes_host_case() {
    let f = fixture().await;
    let mut conn = f.pool.acquire().await.unwrap();
    application(
        "ported",
        "app.example.com:8443",
        None,
        vec!["user".into()],
        true,
    )
    .save(&mut conn)
    .await
    .unwrap();
    drop(conn);
    let start = f
        .router
        .clone()
        .oneshot(request(
            "/.authere/start?redirect_uri=%2Fdashboard%3Ftab%3D1",
            "APP.EXAMPLE.COM:8443",
            None,
        ))
        .await
        .unwrap();
    assert_eq!(start.status(), StatusCode::SEE_OTHER);
    let nonce = cookie(start.headers(), forward::STATE_COOKIE);
    let transfer = f
        .router
        .clone()
        .oneshot(request(
            &path(location(start.headers())),
            "auth.example.com",
            Some(&format!("__Host-authere_token={}", f.pair.access_token)),
        ))
        .await
        .unwrap();
    assert_eq!(transfer.status(), StatusCode::SEE_OTHER);
    assert!(
        location(transfer.headers()).starts_with("https://app.example.com:8443/.authere/callback?")
    );
    let callback = f
        .router
        .clone()
        .oneshot(request(
            &path(location(transfer.headers())),
            "app.example.com:8443",
            Some(&nonce),
        ))
        .await
        .unwrap();
    assert_eq!(callback.status(), StatusCode::SEE_OTHER);
    let session = cookie(callback.headers(), forward::SESSION_COOKIE);
    assert_eq!(
        verify(&f, "APP.EXAMPLE.COM:8443", "/", &session)
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        verify(&f, "app.example.com", "/", &session).await.status(),
        StatusCode::SEE_OTHER
    );
}

#[tokio::test]
async fn credentials_are_isolated_between_path_apps_on_the_same_origin() {
    let f = fixture().await;
    let broad_session = app_session(&f).await;
    let mut conn = f.pool.acquire().await.unwrap();
    application(
        "private",
        "app.example.com",
        Some("/private"),
        vec!["user".into()],
        true,
    )
    .save(&mut conn)
    .await
    .unwrap();
    drop(conn);
    assert_eq!(
        verify(&f, "app.example.com", "/private", &broad_session)
            .await
            .status(),
        StatusCode::SEE_OTHER
    );
    let (callback, nonce) = handoff(&f, "/private").await;
    let response = f
        .router
        .clone()
        .oneshot(request(&callback, "app.example.com", Some(&nonce)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let private_session = cookie(response.headers(), forward::SESSION_COOKIE);
    assert_eq!(
        verify(&f, "app.example.com", "/private", &private_session)
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        verify(&f, "app.example.com", "/dashboard", &private_session)
            .await
            .status(),
        StatusCode::SEE_OTHER
    );
}

#[tokio::test]
async fn auth_origin_is_reserved_even_with_a_matching_wildcard_policy() {
    let f = fixture().await;
    let mut conn = f.pool.acquire().await.unwrap();
    application("wildcard", r".*\.example\.com", None, vec![], true)
        .save(&mut conn)
        .await
        .unwrap();
    drop(conn);
    let response = f
        .router
        .clone()
        .oneshot(request("/.authere/start", "auth.example.com", None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = f.router.clone().oneshot(request(&format!("/api/auth/forward-redirect?redirect_uri=https%3A%2F%2Fauth.example.com%2F&state={}", "a".repeat(64)),
        "auth.example.com", Some(&format!("__Host-authere_token={}", f.pair.access_token)))).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn switch_account_bypasses_automatic_sso_and_preserves_browser_binding() {
    let f = fixture().await;
    let response = f
        .router
        .clone()
        .oneshot(request(
            "/.authere/start?redirect_uri=%2Fdashboard&login=true",
            "app.example.com",
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let login = url::Url::parse(location(response.headers())).unwrap();
    assert_eq!(login.path(), "/login");
    let continuation = login
        .query_pairs()
        .find(|(key, _)| key == "redirect_uri")
        .unwrap()
        .1
        .into_owned();
    assert!(continuation.starts_with("/api/auth/forward-redirect?"));
    let nonce = cookie(response.headers(), forward::STATE_COOKIE);
    assert!(continuation.contains(nonce.split_once('=').unwrap().1));
}

#[tokio::test]
async fn expired_origin_access_renews_sso_without_extending_the_original_session() {
    use ed25519_dalek::pkcs8::EncodePrivateKey;
    let f = fixture().await;
    let mut conn = f.pool.acquire().await.unwrap();
    let mut parent = token::verify_access_token(&f.pair.access_token, &f.key, &mut conn)
        .await
        .unwrap();
    let deadline = parent.session_exp.unwrap();
    parent.exp = forward::now() - 1;
    let der = f.key.to_pkcs8_der().unwrap();
    let expired = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA),
        &parent,
        &jsonwebtoken::EncodingKey::from_ed_der(der.as_bytes()),
    )
    .unwrap();
    drop(conn);
    let start = f
        .router
        .clone()
        .oneshot(request(
            "/.authere/start?redirect_uri=%2Fdashboard",
            "app.example.com",
            None,
        ))
        .await
        .unwrap();
    let nonce = cookie(start.headers(), forward::STATE_COOKIE);
    let transfer = f
        .router
        .clone()
        .oneshot(request(
            &path(location(start.headers())),
            "auth.example.com",
            Some(&format!(
                "__Host-authere_token={expired}; __Host-authere_refresh={}",
                f.pair.refresh_token
            )),
        ))
        .await
        .unwrap();
    assert_eq!(transfer.status(), StatusCode::SEE_OTHER);
    assert!(location(transfer.headers()).starts_with("https://app.example.com/.authere/callback?"));
    let origin_access = cookie(transfer.headers(), "__Host-authere_token");
    let mut conn = f.pool.acquire().await.unwrap();
    let renewed =
        token::verify_access_token(origin_access.split_once('=').unwrap().1, &f.key, &mut conn)
            .await
            .unwrap();
    assert_eq!(renewed.session_exp, Some(deadline));
    drop(conn);
    let callback = f
        .router
        .clone()
        .oneshot(request(
            &path(location(transfer.headers())),
            "app.example.com",
            Some(&nonce),
        ))
        .await
        .unwrap();
    assert_eq!(callback.status(), StatusCode::SEE_OTHER);
    let session = cookie(callback.headers(), forward::SESSION_COOKIE);
    let mut conn = f.pool.acquire().await.unwrap();
    let scoped = forward::verify_session(
        session.split_once('=').unwrap().1,
        "https://app.example.com",
        &f.key,
        &mut conn,
    )
    .await
    .unwrap();
    assert_eq!(scoped.exp, deadline);
}

#[tokio::test]
async fn denied_sso_offer_can_sign_in_as_another_user() {
    let f = fixture().await;
    sqlx::query("DELETE FROM user_roles WHERE user_id = ?")
        .bind(f.user.id)
        .execute(&f.pool)
        .await
        .unwrap();
    let start = f
        .router
        .clone()
        .oneshot(request(
            "/.authere/start?redirect_uri=%2Fdashboard",
            "app.example.com",
            None,
        ))
        .await
        .unwrap();
    let response = f
        .router
        .clone()
        .oneshot(request(
            &path(location(start.headers())),
            "auth.example.com",
            Some(&format!("__Host-authere_token={}", f.pair.access_token)),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(response.into_body(), 100_000)
        .await
        .unwrap();
    let body = String::from_utf8(body.to_vec()).unwrap();
    assert!(body.contains("Sign in as a different user"));
    assert!(body.contains(
        "https://app.example.com/.authere/start?redirect_uri=%2Fdashboard&amp;login=true"
    ));
}

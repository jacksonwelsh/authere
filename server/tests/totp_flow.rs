//! End-to-end TOTP enrollment + login flow over the axum router. Exercises the HTTP
//! surface (JSON shapes, status codes, error bodies) and confirms the replay guard by
//! replaying the activation code.

use std::sync::Arc;
use std::sync::Once;
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
use uuid::Uuid;

use authere_server::AppState;
use authere_server::db::DbEntity;
use authere_server::handlers::{auth, totp};
use authere_server::rate_limit::{RateLimitConfig, RateLimiter};
use authere_server::user::User;
use authere_server::user::auth::Authenticator;
use authere_server::user::auth::totp::{self as totp_core, TOTP_PERIOD};

static INIT_KEY: Once = Once::new();

fn ensure_key_secret() {
    // AES-GCM KEK used to encrypt TOTP secrets at rest. Fixed per-process value is fine in
    // tests — the signing key and TOTP secret stored under this KEK never leak the test DB.
    INIT_KEY.call_once(|| {
        if std::env::var("AUTHERE_KEY_SECRET").is_err() {
            unsafe {
                std::env::set_var(
                    "AUTHERE_KEY_SECRET",
                    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
                );
            }
        }
    });
}

struct Fixture {
    router: Router,
    pool: SqlitePool,
    user_id: Uuid,
    password: String,
}

async fn setup() -> Fixture {
    ensure_key_secret();
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect("sqlite::memory:")
        .await
        .expect("open sqlite");
    sqlx::migrate!("../migrations")
        .run(&pool)
        .await
        .expect("migrate");

    let password = String::from("correct horse battery");
    let mut conn = pool.acquire().await.unwrap();
    let user = User::new("alice".into(), "Alice".into(), Some("alice@example.com".into()));
    user.save(&mut conn).await.unwrap();
    let auth = Authenticator::new_password(password.clone(), user.id).unwrap();
    auth.save(&mut conn).await.unwrap();
    let user_id = user.id;
    drop(conn);

    let signing_key = Arc::new(SigningKey::generate(&mut rand::rngs::OsRng));
    let state = AppState {
        db_pool: pool.clone(),
        login_rate_limiter: RateLimiter::new(RateLimitConfig {
            max_requests: 10_000,
            window: Duration::from_secs(60),
        }),
        register_rate_limiter: RateLimiter::new(RateLimitConfig::default()),
        ldap_bind_rate_limiter: RateLimiter::new(RateLimitConfig::default()),
        scim_rate_limiter: RateLimiter::new(RateLimitConfig::default()),
        signing_key,
        origin: "http://localhost:3000".into(),
    };

    let (router, _) = OpenApiRouter::new()
        .routes(routes!(auth::login))
        .routes(routes!(totp::get_my_totp_status, totp::disable_my_totp))
        .routes(routes!(totp::enroll_my_totp))
        .routes(routes!(totp::activate_my_totp))
        .with_state(state)
        .split_for_parts();

    Fixture { router, pool, user_id, password }
}

fn base32_decode(s: &str) -> Vec<u8> {
    const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    for c in s.chars() {
        let idx = ALPHA.iter().position(|&b| b == c as u8).unwrap_or_else(|| panic!("bad base32 char {c:?}"));
        buf = (buf << 5) | idx as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
        }
    }
    out
}

async fn post_json(router: &Router, uri: &str, bearer: Option<&str>, body: serde_json::Value) -> Response<Body> {
    let mut b = Request::builder().method("POST").uri(uri).header("content-type", "application/json");
    if let Some(t) = bearer {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    let req = b.body(Body::from(serde_json::to_vec(&body).unwrap())).unwrap();
    router.clone().oneshot(req).await.unwrap()
}

async fn body_json(resp: Response<Body>) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 2_000_000).await.unwrap();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::json!(null))
}

async fn body_text(resp: Response<Body>) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), 2_000_000).await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

async fn login_json(router: &Router, username: &str, password: &str, totp_code: Option<&str>) -> Response<Body> {
    let mut body = serde_json::json!({ "username": username, "password": password });
    if let Some(c) = totp_code {
        body["totp_code"] = serde_json::json!(c);
    }
    post_json(router, "/api/login", None, body).await
}

#[tokio::test]
async fn full_enrollment_and_login_flow() {
    let fx = setup().await;

    // 1. Login with just password succeeds (no MFA yet) and returns a token pair.
    let resp = login_json(&fx.router, "alice", &fx.password, None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let token_pair: serde_json::Value = body_json(resp).await;
    let access_token = token_pair["access_token"].as_str().unwrap().to_string();

    // 2. Enroll: must return a base32 secret and an otpauth URI.
    let resp = post_json(&fx.router, "/api/me/totp/enroll", Some(&access_token), serde_json::json!({})).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let enroll: serde_json::Value = body_json(resp).await;
    let secret_b32 = enroll["secret"].as_str().unwrap();
    let uri = enroll["otpauth_uri"].as_str().unwrap();
    assert!(uri.starts_with("otpauth://totp/"));
    assert!(uri.contains(&format!("secret={secret_b32}")));
    let secret_bytes = base32_decode(secret_b32);

    // 3. Activate with a correct code for the current step.
    let now = totp_core::now_epoch();
    let step = (now as u64) / TOTP_PERIOD;
    let correct_code = {
        // Rebuild a local HOTP to compute the expected code without exposing private internals.
        // Relies on the crate's own RFC-4226 verification to cross-check.
        let code = derive_totp(&secret_bytes, step);
        format!("{code:06}")
    };
    let resp = post_json(
        &fx.router,
        "/api/me/totp/activate",
        Some(&access_token),
        serde_json::json!({ "code": correct_code }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let activated: serde_json::Value = body_json(resp).await;
    let recovery_codes = activated["recovery_codes"].as_array().unwrap().clone();
    assert_eq!(recovery_codes.len(), 10);

    // 4. Login without code is rejected with the machine-readable mfa_required marker.
    let resp = login_json(&fx.router, "alice", &fx.password, None).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let text = body_text(resp).await;
    assert!(text.contains("mfa_required"), "expected mfa_required body, got {text:?}");

    // 5. Submitting the activation code again must fail — strict step-replay guard.
    let resp = login_json(&fx.router, "alice", &fx.password, Some(&correct_code)).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let text = body_text(resp).await;
    assert!(text.contains("invalid_totp"), "replayed code must be invalid, got {text:?}");

    // 6. Wait for the step to roll, then log in with a fresh code.
    let next_step = step + 1;
    // Advance clock virtually by computing a code for the next step and using real clock; in
    // practice the test runs so fast we compute code for step+1 but pass the real `now` —
    // verify_code uses `now` for step derivation, so we must sleep until the period rolls.
    // Sleep to the next 30 s boundary, plus a small buffer.
    let wait_s = TOTP_PERIOD - (totp_core::now_epoch() as u64 % TOTP_PERIOD) + 1;
    tokio::time::sleep(Duration::from_secs(wait_s)).await;

    let fresh_code = {
        let s = (totp_core::now_epoch() as u64) / TOTP_PERIOD;
        format!("{:06}", derive_totp(&secret_bytes, s))
    };
    // Skip if somehow `fresh_code` is identical AND we haven't advanced — the 50s+ sleep makes
    // this unlikely but belt-and-braces.
    let _ = next_step; // silence unused when skipping path
    let resp = login_json(&fx.router, "alice", &fx.password, Some(&fresh_code)).await;
    assert_eq!(resp.status(), StatusCode::OK, "fresh-step login must succeed");

    // 7. Bad code is rejected.
    let resp = login_json(&fx.router, "alice", &fx.password, Some("000000")).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // 8. Recovery code works exactly once.
    let rc = recovery_codes[0].as_str().unwrap().to_string();
    let resp = login_json(&fx.router, "alice", &fx.password, Some(&rc)).await;
    assert_eq!(resp.status(), StatusCode::OK, "recovery code must unlock once");
    let resp = login_json(&fx.router, "alice", &fx.password, Some(&rc)).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "recovery code must not replay");

    // 9. Disable TOTP by confirming password.
    let resp = {
        let req = Request::builder()
            .method("DELETE")
            .uri("/api/me/totp")
            .header("authorization", format!("Bearer {access_token}"))
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({ "current_password": &fx.password })).unwrap(),
            ))
            .unwrap();
        fx.router.clone().oneshot(req).await.unwrap()
    };
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // 10. After disable: plain login works again.
    let resp = login_json(&fx.router, "alice", &fx.password, None).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Sanity: row gone from DB.
    let mut conn = fx.pool.acquire().await.unwrap();
    let has_totp = authere_server::user::auth::totp::UserTotp::get(fx.user_id, &mut conn)
        .await
        .unwrap();
    assert!(has_totp.is_none());
}

#[tokio::test]
async fn enroll_rejects_when_totp_already_active() {
    let fx = setup().await;

    // Login and enroll+activate as above (condensed).
    let resp = login_json(&fx.router, "alice", &fx.password, None).await;
    let access_token = body_json(resp).await["access_token"].as_str().unwrap().to_string();

    let resp = post_json(&fx.router, "/api/me/totp/enroll", Some(&access_token), serde_json::json!({})).await;
    let enroll = body_json(resp).await;
    let secret_bytes = base32_decode(enroll["secret"].as_str().unwrap());
    let step = (totp_core::now_epoch() as u64) / TOTP_PERIOD;
    let code = format!("{:06}", derive_totp(&secret_bytes, step));
    let resp = post_json(&fx.router, "/api/me/totp/activate", Some(&access_token), serde_json::json!({ "code": code })).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Second enroll attempt on an activated account must be refused, not silently reset.
    let resp = post_json(&fx.router, "/api/me/totp/enroll", Some(&access_token), serde_json::json!({})).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn activate_without_pending_is_400() {
    let fx = setup().await;
    let resp = login_json(&fx.router, "alice", &fx.password, None).await;
    let access_token = body_json(resp).await["access_token"].as_str().unwrap().to_string();

    let resp = post_json(
        &fx.router,
        "/api/me/totp/activate",
        Some(&access_token),
        serde_json::json!({ "code": "000000" }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// --------------------------------------------------------------------------
// Local TOTP reference implementation — independent of the module under test
// so we aren't tautologically testing verify_code against itself.
// --------------------------------------------------------------------------

fn derive_totp(secret: &[u8], counter: u64) -> u32 {
    use hmac::{Hmac, Mac};
    use sha1::Sha1;
    type H = Hmac<Sha1>;
    let mut mac = <H as Mac>::new_from_slice(secret).unwrap();
    mac.update(&counter.to_be_bytes());
    let r = mac.finalize().into_bytes();
    let offset = (r[19] & 0x0f) as usize;
    let code = (u32::from(r[offset]) & 0x7f) << 24
        | u32::from(r[offset + 1]) << 16
        | u32::from(r[offset + 2]) << 8
        | u32::from(r[offset + 3]);
    code % 1_000_000
}

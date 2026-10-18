//! Real ES256 WebAuthn ceremonies over the HTTP router. The software authenticator
//! below exists only in tests; production delegates verification to webauthn-rs.
use authere_server::{
    AppState,
    browser_security::{BrowserSecurity, protect_browser_requests},
    db::DbEntity,
    handlers::{auth, passkeys, user},
    rate_limit::{RateLimitConfig, RateLimiter},
    user::{
        User,
        auth::{Authenticator, token},
    },
};
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    middleware,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ed25519_dalek::SigningKey;
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    sign::Signer,
};
use serde_cbor_2::Value as Cbor;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tower::ServiceExt;
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

const ORIGIN: &str = "https://auth.example.com";
const PASSWORD: &str = "correct horse battery";
struct Fixture {
    router: Router,
    pool: SqlitePool,
    user_id: Uuid,
    bearer: String,
    other: String,
}
struct Reply {
    status: StatusCode,
    cookies: Vec<String>,
    body: Value,
}

impl Fixture {
    async fn new() -> Self {
        Self::with_limit(10_000).await
    }

    async fn with_limit(max_requests: u32) -> Self {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!("../migrations").run(&pool).await.unwrap();
        let key = Arc::new(SigningKey::generate(&mut rand::rngs::OsRng));
        let mut conn = pool.acquire().await.unwrap();
        let user = User::new("alice".into(), "Alice".into(), None);
        user.save(&mut conn).await.unwrap();
        Authenticator::new_password(PASSWORD.into(), user.id)
            .unwrap()
            .save(&mut conn)
            .await
            .unwrap();
        let bearer = token::generate_token_pair(user.id, vec![], &key, &mut conn)
            .await
            .unwrap()
            .access_token;
        let other_user = User::new("bob".into(), "Bob".into(), None);
        other_user.save(&mut conn).await.unwrap();
        let other = token::generate_token_pair(other_user.id, vec![], &key, &mut conn)
            .await
            .unwrap()
            .access_token;
        drop(conn);
        let limiter = RateLimiter::new(RateLimitConfig {
            max_requests,
            window: Duration::from_secs(60),
        });
        let state = AppState {
            db_pool: pool.clone(),
            login_rate_limiter: limiter.clone(),
            register_rate_limiter: limiter.clone(),
            ldap_bind_rate_limiter: limiter.clone(),
            oidc_token_rate_limiter: limiter,
            signing_key: key,
            signing_kid: "test".into(),
            origin: ORIGIN.into(),
            shutdown: Arc::new(tokio::sync::Notify::new()),
        };
        let (router, _) = OpenApiRouter::new()
            .routes(routes!(passkeys::list))
            .routes(routes!(passkeys::register_start))
            .routes(routes!(passkeys::register_finish))
            .routes(routes!(passkeys::delete))
            .routes(routes!(passkeys::login_start))
            .routes(routes!(passkeys::login_finish))
            .routes(routes!(auth::login))
            .routes(routes!(user::get_me))
            .routes(routes!(auth::browser_refresh))
            .with_state(state)
            .split_for_parts();
        let router = router.layer(middleware::from_fn_with_state(
            BrowserSecurity {
                allowed_origins: vec![ORIGIN.into()],
            },
            protect_browser_requests,
        ));
        Self {
            router,
            pool,
            user_id: user.id,
            bearer,
            other,
        }
    }

    async fn request(
        &self,
        method: &str,
        path: &str,
        bearer: Option<&str>,
        cookie: &str,
        body: Value,
    ) -> Reply {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json");
        if let Some(bearer) = bearer {
            request = request.header("authorization", format!("Bearer {bearer}"));
        }
        if !cookie.is_empty() {
            request = request.header("cookie", cookie);
        }
        let response = self
            .router
            .clone()
            .oneshot(request.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap();
        let status = response.status();
        assert_eq!(response.headers()["cache-control"], "no-store");
        let cookies = response
            .headers()
            .get_all("set-cookie")
            .iter()
            .map(|c| c.to_str().unwrap().to_owned())
            .collect();
        let bytes = axum::body::to_bytes(response.into_body(), 1_000_000)
            .await
            .unwrap();
        let body = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| json!(String::from_utf8_lossy(&bytes)));
        Reply {
            status,
            cookies,
            body,
        }
    }

    async fn start(&self, register: bool) -> Reply {
        let reply = if register {
            self.request(
                "POST",
                "/api/me/passkeys/register/start",
                Some(&self.bearer),
                "",
                json!({"name":"My passkey"}),
            )
            .await
        } else {
            self.request("POST", "/api/auth/passkeys/start", None, "", json!({}))
                .await
        };
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        let cookie = &reply.cookies[0];
        assert!(cookie.contains("HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=300"));
        assert!(reply.body.get("state").is_none());
        reply
    }

    async fn enroll(&self, key: &SoftPasskey) -> Uuid {
        let start = self.start(true).await;
        assert_eq!(
            start.body["authenticatorSelection"]["residentKey"],
            "required"
        );
        assert_eq!(
            start.body["authenticatorSelection"]["requireResidentKey"],
            true
        );
        assert_eq!(
            start.body["authenticatorSelection"]["userVerification"],
            "required"
        );
        assert!(
            start.body["authenticatorSelection"]
                .get("authenticatorAttachment")
                .is_none()
        );
        let response = self
            .request(
                "POST",
                "/api/me/passkeys/register/finish",
                Some(&self.bearer),
                cookie(&start),
                key.registration(&start.body, ORIGIN, true),
            )
            .await;
        assert_eq!(response.status, StatusCode::CREATED, "{}", response.body);
        Uuid::parse_str(response.body["id"].as_str().unwrap()).unwrap()
    }

    async fn finish(&self, start: &Reply, assertion: Value) -> Reply {
        self.request(
            "POST",
            "/api/auth/passkeys/finish",
            None,
            cookie(start),
            assertion,
        )
        .await
    }
}
fn cookie(reply: &Reply) -> &str {
    reply.cookies[0].split(';').next().unwrap()
}

struct SoftPasskey {
    key: PKey<Private>,
    id: Vec<u8>,
    user_id: Uuid,
    synced: bool,
}
impl SoftPasskey {
    fn new(user_id: Uuid) -> Self {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        Self {
            key: PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap(),
            id: Uuid::new_v4().as_bytes().to_vec(),
            user_id,
            synced: false,
        }
    }
    fn client_data(&self, options: &Value, origin: &str, kind: &str) -> Vec<u8> {
        json!({"type": kind, "challenge": options["challenge"], "origin": origin, "crossOrigin": false}).to_string().into_bytes()
    }
    fn data(&self, flags: u8, count: u32) -> Vec<u8> {
        let mut data = Sha256::digest(b"auth.example.com").to_vec();
        data.push(flags | if self.synced { 0x18 } else { 0 });
        data.extend(count.to_be_bytes());
        data
    }
    fn registration(&self, options: &Value, origin: &str, uv: bool) -> Value {
        let ec = self.key.ec_key().unwrap();
        let mut x = BigNum::new().unwrap();
        let mut y = BigNum::new().unwrap();
        ec.public_key()
            .affine_coordinates_gfp(
                ec.group(),
                &mut x,
                &mut y,
                &mut BigNumContext::new().unwrap(),
            )
            .unwrap();
        let cose = Cbor::Map(BTreeMap::from([
            (Cbor::Integer(1), Cbor::Integer(2)),
            (Cbor::Integer(3), Cbor::Integer(-7)),
            (Cbor::Integer(-1), Cbor::Integer(1)),
            (Cbor::Integer(-2), Cbor::Bytes(x.to_vec_padded(32).unwrap())),
            (Cbor::Integer(-3), Cbor::Bytes(y.to_vec_padded(32).unwrap())),
        ]));
        let mut data = self.data(0x41 | if uv { 4 } else { 0 }, 0);
        data.extend([0u8; 16]);
        data.extend((self.id.len() as u16).to_be_bytes());
        data.extend(&self.id);
        data.extend(serde_cbor_2::to_vec(&cose).unwrap());
        let attestation = Cbor::Map(BTreeMap::from([
            (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
            (Cbor::Text("attStmt".into()), Cbor::Map(BTreeMap::new())),
            (Cbor::Text("authData".into()), Cbor::Bytes(data)),
        ]));
        json!({"id":B64.encode(&self.id),"rawId":B64.encode(&self.id),"type":"public-key", "clientExtensionResults":{"credProps":{"rk":true}}, "response":{
            "clientDataJSON":B64.encode(self.client_data(options, origin, "webauthn.create")),
            "attestationObject":B64.encode(serde_cbor_2::to_vec(&attestation).unwrap()),"transports":["internal","hybrid"]
        }})
    }
    fn assertion(&self, options: &Value, origin: &str, uv: bool, counter: u32) -> Value {
        let data = self.data(1 | if uv { 4 } else { 0 }, counter);
        let client = self.client_data(options, origin, "webauthn.get");
        let mut signer = Signer::new(MessageDigest::sha256(), &self.key).unwrap();
        signer.update(&data).unwrap();
        signer.update(&Sha256::digest(&client)).unwrap();
        json!({"id":B64.encode(&self.id),"rawId":B64.encode(&self.id),"type":"public-key","clientExtensionResults":{},"response":{
            "clientDataJSON": B64.encode(client), "authenticatorData":B64.encode(data), "signature":B64.encode(signer.sign_to_vec().unwrap()), "userHandle":B64.encode(self.user_id.as_bytes())
        }})
    }
}

#[tokio::test]
async fn passkey_satisfies_mfa_issues_refreshable_session_and_password_still_requires_totp() {
    let fx = Fixture::new().await;
    let mut key = SoftPasskey::new(fx.user_id);
    key.synced = true;
    let id = fx.enroll(&key).await;
    // Password path returns MFA-required before decrypting the secret.
    sqlx::query("INSERT INTO user_totps (user_id, secret_encrypted, activated_at, created_at, updated_at) VALUES (?, 'unused', 1, 1, 1)")
        .bind(fx.user_id).execute(&fx.pool).await.unwrap();
    let password = fx
        .request(
            "POST",
            "/api/login",
            None,
            "",
            json!({"username":"alice", "password":PASSWORD}),
        )
        .await;
    assert_eq!(password.status, StatusCode::UNAUTHORIZED);
    assert_eq!(password.body["error"], "mfa_required");
    // Synced credentials may always report zero. Repeated fresh ceremonies work.
    for _ in 0..2 {
        let start = fx.start(false).await;
        assert_eq!(start.body["userVerification"], "required");
        let response = fx
            .finish(&start, key.assertion(&start.body, ORIGIN, true, 0))
            .await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.body);
        assert_eq!(response.body["success"], true);
        let cookies = response
            .cookies
            .iter()
            .filter(|c| !c.contains("passkey_login"))
            .map(|c| c.split(';').next().unwrap())
            .collect::<Vec<_>>()
            .join("; ");
        let me = fx
            .request("GET", "/api/me", None, &cookies, json!(null))
            .await;
        assert_eq!(me.status, StatusCode::OK);
        assert_eq!(me.body["username"], "alice");
        assert_eq!(
            fx.request(
                "POST",
                "/api/auth/browser-refresh",
                None,
                &cookies,
                json!({})
            )
            .await
            .status,
            StatusCode::OK
        );
    }
    let list = fx
        .request("GET", "/api/me/passkeys", Some(&fx.bearer), "", json!(null))
        .await;
    assert_eq!(list.body[0]["id"], id.to_string());
    assert!(list.body[0]["last_used_at"].is_number());
    assert!(list.body[0].get("credential").is_none());
}

#[tokio::test]
async fn origin_uv_signature_user_binding_and_counters_are_verified() {
    let fx = Fixture::new().await;
    let key = SoftPasskey::new(fx.user_id);
    fx.enroll(&key).await;
    for (origin, uv) in [
        ("https://evil.example.com", true),
        ("https://auth.example.com:8443", true),
        (ORIGIN, false),
    ] {
        let start = fx.start(false).await;
        assert_eq!(
            fx.finish(&start, key.assertion(&start.body, origin, uv, 1))
                .await
                .status,
            StatusCode::UNAUTHORIZED
        );
    }
    let wrong_key = SoftPasskey::new(fx.user_id);
    let start = fx.start(false).await;
    let mut bad = key.assertion(&start.body, ORIGIN, true, 1);
    bad["response"]["signature"] =
        wrong_key.assertion(&start.body, ORIGIN, true, 1)["response"]["signature"].clone();
    assert_eq!(
        fx.finish(&start, bad).await.status,
        StatusCode::UNAUTHORIZED
    );
    let start = fx.start(false).await;
    let mut bad = key.assertion(&start.body, ORIGIN, true, 1);
    bad["response"]["userHandle"] = json!(B64.encode(Uuid::new_v4().as_bytes()));
    assert_eq!(
        fx.finish(&start, bad).await.status,
        StatusCode::UNAUTHORIZED
    );
    let start = fx.start(false).await;
    assert_eq!(
        fx.finish(&start, key.assertion(&start.body, ORIGIN, true, 2))
            .await
            .status,
        StatusCode::OK
    );
    let start = fx.start(false).await;
    assert_eq!(
        fx.finish(&start, key.assertion(&start.body, ORIGIN, true, 2))
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn challenges_are_browser_bound_expiring_single_use_and_failures_are_consumed() {
    let fx = Fixture::new().await;
    let key = SoftPasskey::new(fx.user_id);
    fx.enroll(&key).await;
    let start = fx.start(false).await;
    let assertion = key.assertion(&start.body, ORIGIN, true, 1);
    assert_eq!(
        fx.request(
            "POST",
            "/api/auth/passkeys/finish",
            None,
            "",
            assertion.clone()
        )
        .await
        .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        fx.finish(&start, assertion.clone()).await.status,
        StatusCode::OK
    );
    assert_eq!(
        fx.finish(&start, assertion).await.status,
        StatusCode::UNAUTHORIZED
    );
    let start = fx.start(false).await;
    sqlx::query("UPDATE passkey_challenges SET expires_at = 0")
        .execute(&fx.pool)
        .await
        .unwrap();
    assert_eq!(
        fx.finish(&start, key.assertion(&start.body, ORIGIN, true, 2))
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    let start = fx.start(false).await;
    let wrong = fx.start(false).await;
    assert_eq!(
        fx.finish(&start, key.assertion(&wrong.body, ORIGIN, true, 2))
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        fx.finish(&start, key.assertion(&start.body, ORIGIN, true, 2))
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn enrollment_checks_account_session_uv_origin_uniqueness_and_replay() {
    let fx = Fixture::new().await;
    let key = SoftPasskey::new(fx.user_id);
    assert_eq!(
        fx.request(
            "POST",
            "/api/me/passkeys/register/start",
            None,
            "",
            json!({"name":"test"})
        )
        .await
        .status,
        StatusCode::UNAUTHORIZED
    );
    for (origin, uv) in [("https://evil.example.com", true), (ORIGIN, false)] {
        let start = fx.start(true).await;
        let response = fx
            .request(
                "POST",
                "/api/me/passkeys/register/finish",
                Some(&fx.bearer),
                cookie(&start),
                key.registration(&start.body, origin, uv),
            )
            .await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    }
    let start = fx.start(true).await;
    let credential = key.registration(&start.body, ORIGIN, true);
    assert_eq!(
        fx.request(
            "POST",
            "/api/me/passkeys/register/finish",
            Some(&fx.other),
            cookie(&start),
            credential.clone()
        )
        .await
        .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        fx.request(
            "POST",
            "/api/me/passkeys/register/finish",
            Some(&fx.bearer),
            cookie(&start),
            credential
        )
        .await
        .status,
        StatusCode::UNAUTHORIZED
    );
    fx.enroll(&key).await;
    let start = fx.start(true).await;
    assert_eq!(
        start.body["excludeCredentials"][0]["id"],
        B64.encode(&key.id)
    );
    assert_eq!(
        fx.request(
            "POST",
            "/api/me/passkeys/register/finish",
            Some(&fx.bearer),
            cookie(&start),
            key.registration(&start.body, ORIGIN, true)
        )
        .await
        .status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn removed_credentials_and_deactivated_accounts_cannot_sign_in() {
    let fx = Fixture::new().await;
    let key = SoftPasskey::new(fx.user_id);
    let id = fx.enroll(&key).await;
    let path = format!("/api/me/passkeys/{id}");
    assert_eq!(
        fx.request("DELETE", &path, Some(&fx.other), "", json!(null))
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    sqlx::query("UPDATE users SET active = 0 WHERE id = ?")
        .bind(fx.user_id)
        .execute(&fx.pool)
        .await
        .unwrap();
    let start = fx.start(false).await;
    assert_eq!(
        fx.finish(&start, key.assertion(&start.body, ORIGIN, true, 1))
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    sqlx::query("UPDATE users SET active = 1 WHERE id = ?")
        .bind(fx.user_id)
        .execute(&fx.pool)
        .await
        .unwrap();
    let start = fx.start(false).await;
    assert_eq!(
        fx.request("DELETE", &path, Some(&fx.bearer), "", json!(null))
            .await
            .status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        fx.finish(&start, key.assertion(&start.body, ORIGIN, true, 1))
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        fx.request("GET", "/api/me", Some(&fx.bearer), "", json!(null))
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn registration_cannot_survive_account_session_revocation() {
    let fx = Fixture::new().await;
    let key = SoftPasskey::new(fx.user_id);
    let start = fx.start(true).await;
    sqlx::query("UPDATE users SET token_version = token_version + 1 WHERE id = ?")
        .bind(fx.user_id)
        .execute(&fx.pool)
        .await
        .unwrap();
    assert_eq!(
        fx.request(
            "POST",
            "/api/me/passkeys/register/finish",
            Some(&fx.bearer),
            cookie(&start),
            key.registration(&start.body, ORIGIN, true)
        )
        .await
        .status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn browser_origin_protection_covers_passkey_ceremonies() {
    let fx = Fixture::new().await;
    let response = fx
        .router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/passkeys/start")
                .header("origin", "https://evil.example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[test]
fn configuration_is_scoped_to_the_exact_secure_auth_origin() {
    for origin in [ORIGIN, "http://localhost:3000"] {
        assert!(passkeys::webauthn(origin).is_ok());
    }
    for origin in [
        "http://auth.example.com",
        "https://127.0.0.1",
        "https://auth.example.com/path",
        "https://auth.example.com?foo=1",
    ] {
        assert!(passkeys::webauthn(origin).is_err());
    }
}

#[tokio::test]
async fn concurrent_finishes_can_create_only_one_session() {
    let fx = Fixture::new().await;
    let key = SoftPasskey::new(fx.user_id);
    fx.enroll(&key).await;
    let start = fx.start(false).await;
    let assertion = key.assertion(&start.body, ORIGIN, true, 1);
    let (a, b) = tokio::join!(
        fx.finish(&start, assertion.clone()),
        fx.finish(&start, assertion)
    );
    let statuses = [a.status, b.status];
    assert!(statuses.contains(&StatusCode::OK));
    assert!(statuses.contains(&StatusCode::UNAUTHORIZED));
}

#[tokio::test]
async fn credential_ids_are_unique_across_accounts() {
    let fx = Fixture::new().await;
    let key = SoftPasskey::new(fx.user_id);
    fx.enroll(&key).await;
    let start = fx
        .request(
            "POST",
            "/api/me/passkeys/register/start",
            Some(&fx.other),
            "",
            json!({"name":"Other account"}),
        )
        .await;
    assert_eq!(start.status, StatusCode::OK);
    let response = fx
        .request(
            "POST",
            "/api/me/passkeys/register/finish",
            Some(&fx.other),
            cookie(&start),
            key.registration(&start.body, ORIGIN, true),
        )
        .await;
    assert_eq!(response.status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn anonymous_passkey_challenges_are_rate_limited() {
    let fx = Fixture::with_limit(1).await;
    fx.start(false).await;
    assert_eq!(
        fx.request("POST", "/api/auth/passkeys/start", None, "", json!({}))
            .await
            .status,
        StatusCode::TOO_MANY_REQUESTS
    );
}

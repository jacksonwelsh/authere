use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Json, State};
use ed25519_dalek::SigningKey;
use sqlx::sqlite::SqlitePoolOptions;

use authere_server::AppState;
use authere_server::audit::AuditContext;
use authere_server::auth_middleware::{AdminUser, AuthUser};
use authere_server::db::DbEntity;
use authere_server::handlers::{admin, registration, user};
use authere_server::rate_limit::{RateLimitConfig, RateLimiter};
use authere_server::settings::{KEY_OPEN_REGISTRATION, open_registration_enabled, set_setting};
use authere_server::user::User;
use authere_server::user::auth::Authenticator;
use authere_server::user::auth::token::generate_token_pair;

async fn state() -> AppState {
    let pool = SqlitePoolOptions::new().max_connections(1).connect("sqlite::memory:").await.unwrap();
    sqlx::migrate!("../migrations").run(&pool).await.unwrap();
    AppState {
        db_pool: pool,
        login_rate_limiter: RateLimiter::new(RateLimitConfig::default()),
        register_rate_limiter: RateLimiter::new(RateLimitConfig::default()),
        ldap_bind_rate_limiter: RateLimiter::new(RateLimitConfig::default()),
        oidc_token_rate_limiter: RateLimiter::new(RateLimitConfig::default()),
        signing_key: Arc::new(SigningKey::generate(&mut rand::rngs::OsRng)),
        signing_kid: "test".into(),
        origin: "https://auth.example.com".into(),
        shutdown: Arc::new(tokio::sync::Notify::new()),
    }
}

fn audit_context() -> AuditContext {
    AuditContext { ip: "127.0.0.1".parse().unwrap(), ip_address: None, user_agent: None }
}

async fn seed_user(state: &AppState) -> User {
    let user = User::new("alice".into(), "Alice Example".into(), Some("alice@example.com".into()));
    let mut conn = state.db_pool.acquire().await.unwrap();
    user.save(&mut conn).await.unwrap();
    Authenticator::new_password("original-password-123".into(), user.id).unwrap().save(&mut conn).await.unwrap();
    user
}

#[tokio::test]
async fn invalid_settings_cannot_partially_enable_registration() {
    let state = state().await;
    let user = seed_user(&state).await;
    let input = serde_json::from_value(serde_json::json!({
        "open_registration": true,
        "ldap": {"enabled": true, "base_dn": "invalid"},
    })).unwrap();
    let result = admin::update_settings(State(state.clone()), audit_context(),
        AdminUser(AuthUser { user_id: user.id, roles: vec!["admin".into()] }), Json(input)).await;
    assert!(result.is_err());
    let mut conn = state.db_pool.acquire().await.unwrap();
    assert!(!open_registration_enabled(&mut conn).await.unwrap());
}

#[tokio::test]
async fn password_change_rolls_back_if_session_revocation_fails() {
    let state = state().await;
    let user = seed_user(&state).await;
    let mut conn = state.db_pool.acquire().await.unwrap();
    generate_token_pair(user.id, vec![], &state.signing_key, &mut conn).await.unwrap();
    sqlx::query("CREATE TRIGGER reject_revocation BEFORE INSERT ON user_access_revocations BEGIN SELECT RAISE(ABORT, 'test failure'); END")
        .execute(&mut *conn).await.unwrap();
    drop(conn);

    let result = user::change_my_password(State(state.clone()), audit_context(),
        AuthUser { user_id: user.id, roles: vec![] },
        Json(user::ChangePasswordInput { current_password: "original-password-123".into(), new_password: "replacement-password-456".into() })).await;
    assert!(result.is_err());

    let mut conn = state.db_pool.acquire().await.unwrap();
    Authenticator::try_password_login(&user, "original-password-123".into(), &mut conn).await.unwrap();
    let revoked: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM refresh_tokens WHERE revoked_at IS NOT NULL")
        .fetch_one(&mut *conn).await.unwrap();
    assert_eq!(revoked, 0, "the failed change must not leave a partially revoked session");
}

#[tokio::test]
async fn clearing_profile_email_persists_null() {
    let state = state().await;
    let user = seed_user(&state).await;
    let input = serde_json::from_value(serde_json::json!({"email": null})).unwrap();
    let _ = user::update_me(State(state.clone()), audit_context(), AuthUser { user_id: user.id, roles: vec![] }, Json(input)).await.unwrap();
    let mut conn = state.db_pool.acquire().await.unwrap();
    assert_eq!(User::get(user.id, &mut conn).await.unwrap().unwrap().email, None);
}

#[tokio::test]
async fn registration_does_not_need_two_pool_connections() {
    let state = state().await;
    let mut conn = state.db_pool.acquire().await.unwrap();
    set_setting(KEY_OPEN_REGISTRATION, "true", &mut conn).await.unwrap();
    drop(conn);
    let result = tokio::time::timeout(Duration::from_secs(2), registration::register(
        State(state), audit_context(), Json(registration::RegisterInput {
            username: "new-user".into(), name: "New User".into(), email: None,
            password: "a-long-test-password".into(), confirm_password: "a-long-test-password".into(), invite_code: None,
        }),
    )).await.expect("registration must release its initial read connection");
    assert!(result.is_ok());
}

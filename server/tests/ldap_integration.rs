//! End-to-end tests for the LDAP adapter, parameterised over the three password modes.
//!
//! We spin up the protocol handler against an in-memory SQLite pool, accept one TCP
//! connection on 127.0.0.1, and exercise BIND + SEARCH via the async `ldap3` client.

use std::sync::Arc;
use std::time::Duration;

use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
};
use ed25519_dalek::SigningKey;
use ldap3::{LdapConnAsync, Scope, SearchEntry};
use sqlx::SqlitePool;
use sqlx::sqlite::SqlitePoolOptions;
use tokio::net::TcpListener;
use uuid::Uuid;

use authere_server::AppState;
use authere_server::app_passwords::AppPassword;
use authere_server::ldap;
use authere_server::rate_limit::{RateLimitConfig, RateLimiter};
use authere_server::settings::{
    KEY_LDAP_BASE_DN, KEY_LDAP_BIND_ADDRESS, KEY_LDAP_ENABLED, KEY_LDAP_PASSWORD_MODE,
    KEY_LDAP_SERVICE_PASSWORD_HASH, LdapPasswordMode, set_setting,
};
use authere_server::user::User;
use authere_server::user::auth::Authenticator;

const SERVICE_PASSWORD: &str = "svc-password-for-testing";
const ALICE_PASSWORD: &str = "alice-primary-password-123";
const BOB_PASSWORD: &str = "bob-primary-password-123";
const BASE_DN: &str = "dc=authere,dc=test";

struct Fixture {
    state: AppState,
    addr: std::net::SocketAddr,
    alice_id: Uuid,
    bob_id: Uuid,
    bob_app_password: String,
}

async fn new_pool() -> SqlitePool {
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

fn hash(pw: &str) -> String {
    Argon2::default()
        .hash_password(pw.as_bytes(), &SaltString::generate(&mut OsRng))
        .unwrap()
        .to_string()
}

async fn seed(pool: &SqlitePool, mode: LdapPasswordMode) -> (Uuid, Uuid, String) {
    let mut conn = pool.acquire().await.unwrap();

    // Alice: no TOTP, has a primary password.
    let alice_id = Uuid::now_v7();
    sqlx::query!(
        "INSERT INTO users (id, username, name, email) VALUES (?, ?, ?, ?)",
        alice_id,
        "alice",
        "Alice Example",
        "alice@example.com"
    )
    .execute(&mut *conn)
    .await
    .unwrap();
    let alice_auth = Authenticator::new_password(ALICE_PASSWORD.to_string(), alice_id).unwrap();
    let alice_hash = match alice_auth.scheme {
        authere_server::user::auth::AuthenticationScheme::Password(h) => h,
        _ => unreachable!(),
    };
    let alice_auth_id = Uuid::now_v7();
    sqlx::query!(
        "INSERT INTO authenticators (id, type, value, owner_id) VALUES (?, 'password', ?, ?)",
        alice_auth_id,
        alice_hash,
        alice_id
    )
    .execute(&mut *conn)
    .await
    .unwrap();

    // Bob: has TOTP + primary password.
    let bob_id = Uuid::now_v7();
    sqlx::query!(
        "INSERT INTO users (id, username, name, email) VALUES (?, ?, ?, NULL)",
        bob_id,
        "bob",
        "Bob Example"
    )
    .execute(&mut *conn)
    .await
    .unwrap();
    let bob_auth = Authenticator::new_password(BOB_PASSWORD.to_string(), bob_id).unwrap();
    let bob_hash = match bob_auth.scheme {
        authere_server::user::auth::AuthenticationScheme::Password(h) => h,
        _ => unreachable!(),
    };
    let bob_auth_id = Uuid::now_v7();
    sqlx::query!(
        "INSERT INTO authenticators (id, type, value, owner_id) VALUES (?, 'password', ?, ?)",
        bob_auth_id,
        bob_hash,
        bob_id
    )
    .execute(&mut *conn)
    .await
    .unwrap();
    let bob_totp_id = Uuid::now_v7();
    sqlx::query!(
        "INSERT INTO authenticators (id, type, value, owner_id) VALUES (?, 'totp', 'JBSWY3DPEHPK3PXP', ?)",
        bob_totp_id,
        bob_id
    )
    .execute(&mut *conn)
    .await
    .unwrap();

    // Roles: admin + user (pre-inserted by migration). Assign alice -> admin, bob -> user.
    let admin_id: Uuid = sqlx::query_scalar!(
        r#"SELECT id as "id: Uuid" FROM roles WHERE name = 'admin'"#
    )
    .fetch_one(&mut *conn)
    .await
    .unwrap();
    let user_role_id: Uuid = sqlx::query_scalar!(
        r#"SELECT id as "id: Uuid" FROM roles WHERE name = 'user'"#
    )
    .fetch_one(&mut *conn)
    .await
    .unwrap();
    sqlx::query!(
        "INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)",
        alice_id,
        admin_id
    )
    .execute(&mut *conn)
    .await
    .unwrap();
    sqlx::query!(
        "INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)",
        bob_id,
        user_role_id
    )
    .execute(&mut *conn)
    .await
    .unwrap();

    // App password for Bob only (so we can test TOTP path in primary_and_app).
    let (_rec, bob_app_password) = AppPassword::create(bob_id, "Jellyfin", &mut conn)
        .await
        .unwrap();

    // Settings: LDAP config.
    set_setting(KEY_LDAP_ENABLED, "true", &mut conn).await.unwrap();
    set_setting(KEY_LDAP_BASE_DN, BASE_DN, &mut conn).await.unwrap();
    set_setting(KEY_LDAP_BIND_ADDRESS, "127.0.0.1:0", &mut conn)
        .await
        .unwrap();
    set_setting(KEY_LDAP_SERVICE_PASSWORD_HASH, &hash(SERVICE_PASSWORD), &mut conn)
        .await
        .unwrap();
    set_setting(KEY_LDAP_PASSWORD_MODE, mode.as_str(), &mut conn)
        .await
        .unwrap();

    (alice_id, bob_id, bob_app_password)
}

async fn start_server(mode: LdapPasswordMode) -> Fixture {
    let pool = new_pool().await;
    let (alice_id, bob_id, bob_app_password) = seed(&pool, mode).await;

    // Ed25519 signing key unused by LDAP; just generate one.
    let signing_key = Arc::new(SigningKey::generate(&mut rand::rngs::OsRng));

    let ldap_bind_rate_limiter = RateLimiter::new(RateLimitConfig {
        max_requests: 1000,
        window: Duration::from_secs(60),
    });
    let state = AppState {
        db_pool: pool,
        login_rate_limiter: RateLimiter::new(RateLimitConfig::default()),
        register_rate_limiter: RateLimiter::new(RateLimitConfig::default()),
        ldap_bind_rate_limiter,
        scim_rate_limiter: RateLimiter::new(RateLimitConfig::default()),
        signing_key,
        origin: String::from("http://localhost:3000"),
    };

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let spawn_state = state.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, peer)) = listener.accept().await else { break };
            let per_conn_state = spawn_state.clone();
            tokio::spawn(async move {
                let _ = ldap::handle_connection(stream, per_conn_state, peer).await;
            });
        }
    });

    Fixture {
        state,
        addr,
        alice_id,
        bob_id,
        bob_app_password,
    }
}

async fn connect(addr: std::net::SocketAddr) -> ldap3::Ldap {
    let url = format!("ldap://{}", addr);
    let (conn, ldap) = LdapConnAsync::new(&url).await.expect("ldap connect");
    tokio::spawn(async move {
        let _ = conn.drive().await;
    });
    ldap
}

fn user_dn(username: &str) -> String {
    format!("uid={},ou=people,{}", username, BASE_DN)
}

fn service_dn() -> String {
    format!("cn=service,{}", BASE_DN)
}

fn group_dn(role: &str) -> String {
    format!("cn={},ou=groups,{}", role, BASE_DN)
}

// --------------------------------------------------------------------------------
// Common behaviours (apply in all modes)
// --------------------------------------------------------------------------------

#[tokio::test]
async fn service_bind_and_user_search() {
    let fx = start_server(LdapPasswordMode::PrimaryAndApp).await;
    let mut ldap = connect(fx.addr).await;

    let res = ldap
        .simple_bind(&service_dn(), SERVICE_PASSWORD)
        .await
        .unwrap();
    assert_eq!(res.rc, 0, "service bind should succeed");

    let (entries, _res) = ldap
        .search(
            &format!("ou=people,{}", BASE_DN),
            Scope::OneLevel,
            "(uid=alice)",
            vec!["uid", "cn", "mail", "memberOf"],
        )
        .await
        .unwrap()
        .success()
        .unwrap();
    assert_eq!(entries.len(), 1);
    let e = SearchEntry::construct(entries.into_iter().next().unwrap());
    assert_eq!(e.dn, user_dn("alice"));
    assert_eq!(e.attrs.get("uid").unwrap(), &vec!["alice".to_string()]);
    let member_of = e.attrs.get("memberOf").unwrap();
    assert!(member_of.contains(&group_dn("admin")));

    let _ = ldap.unbind().await;
    let _ = fx.state;
    let _ = fx.alice_id;
    let _ = fx.bob_id;
    let _ = fx.bob_app_password;
}

#[tokio::test]
async fn bad_service_password_rejected() {
    let fx = start_server(LdapPasswordMode::PrimaryAndApp).await;
    let mut ldap = connect(fx.addr).await;
    let res = ldap.simple_bind(&service_dn(), "wrong").await.unwrap();
    assert_ne!(res.rc, 0, "wrong password must not succeed");
}

#[tokio::test]
async fn anonymous_root_dse_lookup() {
    let fx = start_server(LdapPasswordMode::PrimaryAndApp).await;
    let mut ldap = connect(fx.addr).await;
    let (entries, _res) = ldap
        .search("", Scope::Base, "(objectClass=*)", vec!["namingContexts", "supportedLDAPVersion"])
        .await
        .unwrap()
        .success()
        .unwrap();
    assert_eq!(entries.len(), 1);
    let e = SearchEntry::construct(entries.into_iter().next().unwrap());
    assert_eq!(e.attrs.get("namingContexts").unwrap(), &vec![BASE_DN.to_string()]);
}

// --------------------------------------------------------------------------------
// Mode: primary_and_app
// --------------------------------------------------------------------------------

#[tokio::test]
async fn primary_and_app_non_totp_user_can_use_primary() {
    let fx = start_server(LdapPasswordMode::PrimaryAndApp).await;
    let mut ldap = connect(fx.addr).await;
    let res = ldap
        .simple_bind(&user_dn("alice"), ALICE_PASSWORD)
        .await
        .unwrap();
    assert_eq!(res.rc, 0, "alice primary password must work in primary_and_app");
}

#[tokio::test]
async fn primary_and_app_totp_user_cannot_use_primary() {
    let fx = start_server(LdapPasswordMode::PrimaryAndApp).await;
    let mut ldap = connect(fx.addr).await;
    let res = ldap.simple_bind(&user_dn("bob"), BOB_PASSWORD).await.unwrap();
    assert_ne!(res.rc, 0, "bob has TOTP — primary password must be rejected");
}

#[tokio::test]
async fn primary_and_app_totp_user_can_use_app_password() {
    let fx = start_server(LdapPasswordMode::PrimaryAndApp).await;
    let mut ldap = connect(fx.addr).await;
    let res = ldap
        .simple_bind(&user_dn("bob"), &fx.bob_app_password)
        .await
        .unwrap();
    assert_eq!(res.rc, 0, "bob's app password must succeed even with TOTP enabled");
}

// --------------------------------------------------------------------------------
// Mode: app_only
// --------------------------------------------------------------------------------

#[tokio::test]
async fn app_only_rejects_primary_for_everyone() {
    let fx = start_server(LdapPasswordMode::AppOnly).await;
    let mut ldap = connect(fx.addr).await;
    let res_a = ldap
        .simple_bind(&user_dn("alice"), ALICE_PASSWORD)
        .await
        .unwrap();
    assert_ne!(res_a.rc, 0, "alice primary must be rejected in app_only");
    let res_b = ldap.simple_bind(&user_dn("bob"), BOB_PASSWORD).await.unwrap();
    assert_ne!(res_b.rc, 0, "bob primary must be rejected in app_only");
}

#[tokio::test]
async fn app_only_accepts_app_password() {
    let fx = start_server(LdapPasswordMode::AppOnly).await;
    let mut ldap = connect(fx.addr).await;
    let res = ldap
        .simple_bind(&user_dn("bob"), &fx.bob_app_password)
        .await
        .unwrap();
    assert_eq!(res.rc, 0);
}

// --------------------------------------------------------------------------------
// Mode: primary_only
// --------------------------------------------------------------------------------

#[tokio::test]
async fn primary_only_accepts_primary_for_non_totp_user() {
    let fx = start_server(LdapPasswordMode::PrimaryOnly).await;
    let mut ldap = connect(fx.addr).await;
    let res = ldap
        .simple_bind(&user_dn("alice"), ALICE_PASSWORD)
        .await
        .unwrap();
    assert_eq!(res.rc, 0);
}

#[tokio::test]
async fn primary_only_rejects_totp_user() {
    let fx = start_server(LdapPasswordMode::PrimaryOnly).await;
    let mut ldap = connect(fx.addr).await;
    let res = ldap.simple_bind(&user_dn("bob"), BOB_PASSWORD).await.unwrap();
    assert_ne!(res.rc, 0, "TOTP users cannot bind in primary_only mode");
    let res = ldap
        .simple_bind(&user_dn("bob"), &fx.bob_app_password)
        .await
        .unwrap();
    assert_ne!(
        res.rc, 0,
        "app passwords are also rejected in primary_only mode"
    );
}

#[tokio::test]
async fn bind_rejected_for_deactivated_user() {
    // Deactivation is the SCIM control surface for revoking access; LDAP bind must honor it.
    let fx = start_server(LdapPasswordMode::PrimaryAndApp).await;

    let mut conn = fx.state.db_pool.acquire().await.unwrap();
    sqlx::query!("UPDATE users SET active = 0 WHERE id = ?", fx.alice_id)
        .execute(&mut *conn)
        .await
        .unwrap();
    drop(conn);

    let mut ldap = connect(fx.addr).await;
    let res = ldap
        .simple_bind(&user_dn("alice"), ALICE_PASSWORD)
        .await
        .unwrap();
    assert_ne!(res.rc, 0, "deactivated user must not be able to LDAP bind");
}

#[tokio::test]
async fn subtree_search_includes_users_and_groups() {
    let fx = start_server(LdapPasswordMode::PrimaryAndApp).await;
    let mut ldap = connect(fx.addr).await;

    ldap.simple_bind(&service_dn(), SERVICE_PASSWORD).await.unwrap();
    let (entries, _res) = ldap
        .search(BASE_DN, Scope::Subtree, "(objectClass=*)", vec!["dn"])
        .await
        .unwrap()
        .success()
        .unwrap();

    let dns: Vec<String> = entries
        .into_iter()
        .map(|e| SearchEntry::construct(e).dn)
        .collect();
    assert!(dns.contains(&user_dn("alice")));
    assert!(dns.contains(&group_dn("admin")));
    assert!(dns.contains(&group_dn("user")));

    let _ = User::list; // silence unused warning in some configurations
}

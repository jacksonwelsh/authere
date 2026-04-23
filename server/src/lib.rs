//! Library crate for authere_server. Splits out the modules and `AppState` so integration
//! tests (which can't link against a `bin`-only crate) can build on them. `main.rs` remains
//! the binary entry point.

use std::sync::Arc;

use axum::extract::FromRef;
use ed25519_dalek::SigningKey;
use sqlx::SqlitePool;
use tokio::sync::Notify;

use crate::rate_limit::RateLimiter;

pub mod app_passwords;
pub mod application;
pub mod audit;
pub mod auth_middleware;
pub mod cli;
pub mod db;
pub mod errors;
pub mod handlers;
pub mod invitation;
pub mod ldap;
pub mod rate_limit;
pub mod role;
pub mod scim;
pub mod settings;
pub mod static_files;
pub mod user;

#[derive(Clone)]
pub struct AppState {
    pub db_pool: SqlitePool,
    pub login_rate_limiter: RateLimiter,
    pub register_rate_limiter: RateLimiter,
    pub ldap_bind_rate_limiter: RateLimiter,
    pub scim_rate_limiter: RateLimiter,
    pub signing_key: Arc<SigningKey>,
    pub origin: String,
    pub shutdown: Arc<Notify>,
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

/// Newtype over the SCIM rate limiter so `ScimAuth` can extract it via `FromRef` without
/// colliding with the other RateLimiter fields on AppState.
#[derive(Clone)]
pub struct ScimRateLimiter(pub RateLimiter);

impl FromRef<AppState> for ScimRateLimiter {
    fn from_ref(state: &AppState) -> Self {
        ScimRateLimiter(state.scim_rate_limiter.clone())
    }
}

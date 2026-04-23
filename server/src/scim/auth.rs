//! `ScimAuth` extractor — bearer token authentication for `/scim/v2/*` endpoints.
//!
//! Deliberately independent from the JWT-based `AuthUser`: SCIM tokens must not be accepted
//! as session tokens for any other endpoint, and user sessions must not be accepted here.
//! Credential surface mixing is a common IdP integration bug class.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use axum::extract::{ConnectInfo, FromRef, FromRequestParts};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use sqlx::SqlitePool;

use crate::ScimRateLimiter;
use crate::audit::AuditContext;
use crate::scim::error::ScimError;
use crate::scim::token::{self, ScimTokenRecord, TOKEN_PREFIX};

/// Extracted identity for an authenticated SCIM client — the validated token record plus the
/// audit context we'll need to write any downstream log entries.
#[derive(Debug, Clone)]
pub struct ScimAuth {
    pub token: ScimTokenRecord,
    pub audit: AuditContext,
}

/// Pull the peer IP from a request (mirrors `AuditContext` extraction). Used as the rate
/// limiter key so one misbehaving IdP egress can't starve another tenant.
fn peer_ip(parts: &Parts) -> IpAddr {
    parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
}

fn extract_bearer(parts: &Parts) -> Option<&str> {
    parts
        .headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

impl<S> FromRequestParts<S> for ScimAuth
where
    SqlitePool: FromRef<S>,
    ScimRateLimiter: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ScimError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let pool = SqlitePool::from_ref(state);
        let ScimRateLimiter(rate_limiter) = ScimRateLimiter::from_ref(state);

        let bearer = extract_bearer(parts)
            .map(|s| s.to_string())
            .ok_or_else(ScimError::unauthorized)?;
        if !bearer.starts_with(TOKEN_PREFIX) {
            return Err(ScimError::unauthorized());
        }

        if rate_limiter.check(peer_ip(parts)).await.is_err() {
            return Err(ScimError::rate_limited());
        }

        let audit = AuditContext::from_request_parts(parts, state)
            .await
            .expect("AuditContext is infallible");

        let mut conn = pool
            .acquire()
            .await
            .map_err(|e| ScimError::internal(format!("db acquire: {e}")))?;

        match token::verify(&bearer, &mut conn).await? {
            Some(record) => Ok(ScimAuth {
                token: record,
                audit,
            }),
            None => Err(ScimError::unauthorized()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;

    fn parts_with_headers(headers: &[(&str, &str)]) -> Parts {
        let mut b = Request::builder();
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(()).unwrap().into_parts().0
    }

    #[test]
    fn extract_bearer_reads_prefix() {
        let p = parts_with_headers(&[("Authorization", "Bearer authere_scim_abc")]);
        assert_eq!(extract_bearer(&p), Some("authere_scim_abc"));
    }

    #[test]
    fn extract_bearer_none_when_missing() {
        let p = parts_with_headers(&[]);
        assert!(extract_bearer(&p).is_none());
    }

    #[test]
    fn extract_bearer_ignores_basic_auth() {
        let p = parts_with_headers(&[("Authorization", "Basic Zm9vOmJhcg==")]);
        assert!(extract_bearer(&p).is_none());
    }

    #[test]
    fn extract_bearer_ignores_empty_bearer() {
        let p = parts_with_headers(&[("Authorization", "Bearer ")]);
        // Our stripping returns Some("") which is still a bearer but we'll reject downstream
        // via the prefix check.
        assert_eq!(extract_bearer(&p), Some(""));
    }
}

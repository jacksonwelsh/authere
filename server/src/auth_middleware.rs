use std::sync::Arc;

use axum::{
    extract::{FromRef, FromRequestParts},
    http::{header::AUTHORIZATION, request::Parts},
};
use ed25519_dalek::SigningKey;
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::errors::AppError;
use crate::role::ROLE_ADMIN;
use crate::user::auth::token::verify_access_token;

/// Extract a token string from either the Authorization header or the authere_token cookie.
fn extract_token(parts: &Parts) -> Option<String> {
    // Authorization: Bearer <token>
    if let Some(bearer) = parts
        .headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        return Some(bearer.to_owned());
    }

    // Cookie: authere_token=<token>
    parts
        .headers
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies
                .split(';')
                .map(|s| s.trim())
                .find(|s| s.starts_with("authere_token="))
                .and_then(|s| s.strip_prefix("authere_token="))
                .map(|s| s.to_owned())
        })
}

/// Authenticated user information extracted from JWT
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: Uuid,
    pub roles: Vec<String>,
}

impl AuthUser {
    /// Check if user has a specific role
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }

    /// Check if user has the admin role
    pub fn is_admin(&self) -> bool {
        self.has_role(ROLE_ADMIN)
    }
}

impl<S> FromRequestParts<S> for AuthUser
where
    SqlitePool: FromRef<S>,
    Arc<SigningKey>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let pool = SqlitePool::from_ref(state);
        let signing_key = Arc::<SigningKey>::from_ref(state);

        let token = extract_token(parts).ok_or(AppError::AuthenticationRequired)?;

        let mut conn = pool.acquire().await?;
        let claims = verify_access_token(&token, &signing_key, &mut conn).await?;

        let user_id = Uuid::parse_str(&claims.sub)
            .map_err(|_| AppError::InternalError("Invalid user ID in token".to_string()))?;

        Ok(AuthUser {
            user_id,
            roles: claims.roles,
        })
    }
}

/// Extractor that requires the user to have admin role
#[derive(Debug, Clone)]
pub struct AdminUser(pub AuthUser);

impl<S> FromRequestParts<S> for AdminUser
where
    SqlitePool: FromRef<S>,
    Arc<SigningKey>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth_user = AuthUser::from_request_parts(parts, state).await?;

        if !auth_user.is_admin() {
            return Err(AppError::Forbidden);
        }

        Ok(AdminUser(auth_user))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;

    fn make_parts(headers: Vec<(&str, &str)>) -> Parts {
        let mut builder = Request::builder();
        for (k, v) in headers {
            builder = builder.header(k, v);
        }
        let (parts, _) = builder.body(()).unwrap().into_parts();
        parts
    }

    #[test]
    fn extract_token_from_bearer_header() {
        let parts = make_parts(vec![("Authorization", "Bearer my-jwt-token")]);
        assert_eq!(extract_token(&parts).unwrap(), "my-jwt-token");
    }

    #[test]
    fn extract_token_from_cookie() {
        let parts = make_parts(vec![("Cookie", "other=val; authere_token=cookie-jwt; foo=bar")]);
        assert_eq!(extract_token(&parts).unwrap(), "cookie-jwt");
    }

    #[test]
    fn extract_token_bearer_takes_precedence() {
        let parts = make_parts(vec![
            ("Authorization", "Bearer bearer-jwt"),
            ("Cookie", "authere_token=cookie-jwt"),
        ]);
        assert_eq!(extract_token(&parts).unwrap(), "bearer-jwt");
    }

    #[test]
    fn extract_token_returns_none_when_missing() {
        let parts = make_parts(vec![]);
        assert!(extract_token(&parts).is_none());
    }

    #[test]
    fn extract_token_ignores_non_bearer_auth() {
        let parts = make_parts(vec![("Authorization", "Basic dXNlcjpwYXNz")]);
        assert!(extract_token(&parts).is_none());
    }

    #[test]
    fn extract_token_ignores_unrelated_cookies() {
        let parts = make_parts(vec![("Cookie", "session=abc; other=def")]);
        assert!(extract_token(&parts).is_none());
    }

    #[test]
    fn auth_user_has_role() {
        let user = AuthUser {
            user_id: Uuid::nil(),
            roles: vec!["admin".into(), "user".into()],
        };
        assert!(user.has_role("admin"));
        assert!(user.has_role("user"));
        assert!(!user.has_role("superadmin"));
    }

    #[test]
    fn auth_user_is_admin() {
        let admin = AuthUser {
            user_id: Uuid::nil(),
            roles: vec!["admin".into()],
        };
        assert!(admin.is_admin());

        let regular = AuthUser {
            user_id: Uuid::nil(),
            roles: vec!["user".into()],
        };
        assert!(!regular.is_admin());
    }

    #[test]
    fn auth_user_empty_roles() {
        let user = AuthUser {
            user_id: Uuid::nil(),
            roles: vec![],
        };
        assert!(!user.has_role("anything"));
        assert!(!user.is_admin());
    }
}

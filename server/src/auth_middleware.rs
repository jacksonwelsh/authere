use axum::{
    extract::{FromRef, FromRequestParts},
    http::{header::AUTHORIZATION, request::Parts},
};
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::errors::AppError;
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
        self.has_role("admin")
    }
}

impl<S> FromRequestParts<S> for AuthUser
where
    SqlitePool: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let pool = SqlitePool::from_ref(state);

        let token = extract_token(parts).ok_or(AppError::AuthenticationRequired)?;

        let mut conn = pool.acquire().await?;
        let claims = verify_access_token(&token, &mut conn).await?;

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

pub mod admin;
pub mod application;
pub mod auth;
pub mod registration;
pub mod role;
pub mod user;

use axum::response::{IntoResponse, Response};

use crate::errors::AppError;
use crate::rate_limit::RateLimitExceeded;

/// Cookie configuration
pub const AUTH_COOKIE_NAME: &str = "authere_token";
pub const REFRESH_COOKIE_NAME: &str = "authere_refresh";

/// Build Set-Cookie header for authentication
pub fn build_auth_cookie(token: &str, max_age_secs: i64) -> String {
    format!(
        "{}={}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={}",
        AUTH_COOKIE_NAME, token, max_age_secs
    )
}

/// Build Set-Cookie header for refresh token
pub fn build_refresh_cookie(token: &str, max_age_secs: i64) -> String {
    format!(
        "{}={}; HttpOnly; Secure; SameSite=Strict; Path=/auth; Max-Age={}",
        REFRESH_COOKIE_NAME, token, max_age_secs
    )
}

/// Clear authentication cookies
pub fn clear_auth_cookies() -> Vec<String> {
    vec![
        format!("{}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0", AUTH_COOKIE_NAME),
        format!("{}=; HttpOnly; Secure; SameSite=Strict; Path=/auth; Max-Age=0", REFRESH_COOKIE_NAME),
    ]
}

/// Error type that can be either an AppError or a RateLimitExceeded
pub enum LoginError {
    App(AppError),
    RateLimit(RateLimitExceeded),
}

impl IntoResponse for LoginError {
    fn into_response(self) -> Response {
        match self {
            LoginError::App(e) => e.into_response(),
            LoginError::RateLimit(e) => e.into_response(),
        }
    }
}

impl From<AppError> for LoginError {
    fn from(e: AppError) -> Self {
        LoginError::App(e)
    }
}

impl From<sqlx::Error> for LoginError {
    fn from(e: sqlx::Error) -> Self {
        LoginError::App(AppError::from(e))
    }
}

pub enum RegisterError {
    App(AppError),
    RateLimit(RateLimitExceeded),
}

impl IntoResponse for RegisterError {
    fn into_response(self) -> Response {
        match self {
            RegisterError::App(e) => e.into_response(),
            RegisterError::RateLimit(e) => e.into_response(),
        }
    }
}

impl From<AppError> for RegisterError {
    fn from(e: AppError) -> Self {
        RegisterError::App(e)
    }
}

impl From<sqlx::Error> for RegisterError {
    fn from(e: sqlx::Error) -> Self {
        RegisterError::App(AppError::from(e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    #[test]
    fn test_build_auth_cookie_format() {
        let cookie = build_auth_cookie("my-token", 900);
        assert!(cookie.contains("authere_token=my-token"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("SameSite=Lax"));
        assert!(cookie.contains("Path=/"));
        assert!(cookie.contains("Max-Age=900"));
    }

    #[test]
    fn test_build_refresh_cookie_format() {
        let cookie = build_refresh_cookie("refresh-tok", 604800);
        assert!(cookie.contains("authere_refresh=refresh-tok"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains("Path=/auth"));
        assert!(cookie.contains("Max-Age=604800"));
    }

    #[test]
    fn test_clear_auth_cookies() {
        let cookies = clear_auth_cookies();
        assert_eq!(cookies.len(), 2);

        assert!(cookies[0].contains("authere_token="));
        assert!(cookies[0].contains("Max-Age=0"));
        assert!(cookies[0].contains("Path=/"));

        assert!(cookies[1].contains("authere_refresh="));
        assert!(cookies[1].contains("Max-Age=0"));
        assert!(cookies[1].contains("Path=/auth"));
    }

    #[test]
    fn test_cookie_constants() {
        assert_eq!(AUTH_COOKIE_NAME, "authere_token");
        assert_eq!(REFRESH_COOKIE_NAME, "authere_refresh");
    }

    #[test]
    fn test_login_error_from_app_error() {
        let err: LoginError = AppError::NotFound.into();
        assert!(matches!(err, LoginError::App(AppError::NotFound)));
    }

    #[test]
    fn test_register_error_from_app_error() {
        let err: RegisterError = AppError::Forbidden.into();
        assert!(matches!(err, RegisterError::App(AppError::Forbidden)));
    }

    #[test]
    fn test_login_error_into_response() {
        let err = LoginError::App(AppError::AuthenticationRequired);
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let err = LoginError::RateLimit(RateLimitExceeded {
            retry_after: std::time::Duration::from_secs(30),
        });
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn test_register_error_into_response() {
        let err = RegisterError::App(AppError::InputError(vec!["bad".into()]));
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let err = RegisterError::RateLimit(RateLimitExceeded {
            retry_after: std::time::Duration::from_secs(10),
        });
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}

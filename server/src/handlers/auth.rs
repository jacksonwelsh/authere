use axum::extract::{self, Query, State};
use axum::http::header::{self, HeaderMap, HeaderName, HeaderValue};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::AppState;
use crate::audit::{AuditContext, log_login_failed, log_login_success, log_logout, log_token_refresh};
use crate::db::DbEntity;
use crate::errors::AppError;
use crate::handlers::{LoginError, build_auth_cookie, build_refresh_cookie, clear_auth_cookies};
use crate::rate_limit::RateLimitExceeded;
use crate::user::auth::Authenticator;
use crate::user::auth::token::{self, REFRESH_TOKEN_LIFETIME, TokenPair, generate_token_pair, verify_and_revoke_refresh_token, revoke_user_access_tokens};
use crate::user::{LoginInput, User};

const AUTH_TAG: &str = "auth";

#[derive(Debug, Deserialize, ToSchema)]
pub struct RefreshTokenInput {
    pub refresh_token: String,
}

/// Response headers for successful forward auth
fn build_auth_headers(user: &User, roles: &[String], email: Option<&str>) -> HeaderMap {
    let mut headers = HeaderMap::new();

    headers.insert(
        HeaderName::from_static("x-auth-user"),
        HeaderValue::from_str(&user.id.to_string()).unwrap_or_else(|_| HeaderValue::from_static("")),
    );

    headers.insert(
        HeaderName::from_static("x-auth-username"),
        HeaderValue::from_str(&user.username).unwrap_or_else(|_| HeaderValue::from_static("")),
    );

    headers.insert(
        HeaderName::from_static("x-auth-roles"),
        HeaderValue::from_str(&roles.join(",")).unwrap_or_else(|_| HeaderValue::from_static("")),
    );

    if let Some(email) = email {
        if let Ok(value) = HeaderValue::from_str(email) {
            headers.insert(HeaderName::from_static("x-auth-email"), value);
        }
    }

    headers
}

#[utoipa::path(
    post,
    path = "/api/login",
    request_body(
        content = LoginInput,
        example = json!(LoginInput {
            username: String::from("bob_burger"),
            password: String::from("hunter2hunter2"),
        }),
    ),
    responses(
        (status = 200, description = "Successful login", body = TokenPair),
        (status = 400, description = "Invalid username or password"),
        (status = 401, description = "Incorrect username or password"),
        (status = 429, description = "Too many login attempts"),
        (status = 500, description = "Internal server error")
    ),
    tag = AUTH_TAG,
)]
pub async fn login(
    State(state): State<AppState>,
    audit_ctx: AuditContext,
    extract::Json(input): extract::Json<LoginInput>,
) -> Result<axum::Json<TokenPair>, LoginError> {
    if let Err(retry_after) = state.login_rate_limiter.check(audit_ctx.ip).await {
        warn!(ip = %audit_ctx.ip, "login rate limit exceeded");
        return Err(LoginError::RateLimit(RateLimitExceeded { retry_after }));
    }

    let mut conn = state.db_pool.acquire().await?;
    if let Err(msg) = Authenticator::validate_password(&input.password) {
        return Err(AppError::InputError(vec![msg]).into());
    }

    let username = input.username.clone();
    let user = match User::login(input, &mut conn).await {
        Ok(user) => user,
        Err(e) => {
            state.login_rate_limiter.record_failure(audit_ctx.ip).await;
            let failed_user_id = User::get_by_username(&username, &mut conn).await.ok().flatten().map(|u| u.id);
            warn!(username = %username, ip = %audit_ctx.ip, "login failed");
            let _ = log_login_failed(&username, failed_user_id, &audit_ctx, &mut conn).await;
            return Err(e.into());
        }
    };

    let roles = user.get_roles(&mut conn).await?;
    let token_pair = generate_token_pair(user.id, roles, &state.signing_key, &mut conn).await?;

    info!(user_id = %user.id, username = %user.username, "login successful");
    let _ = log_login_success(user.id, &audit_ctx, &mut conn).await;

    Ok(axum::Json(token_pair))
}

#[utoipa::path(
    post,
    path = "/api/auth/refresh",
    request_body(content = RefreshTokenInput),
    responses(
        (status = 200, description = "Token refreshed", body = TokenPair),
        (status = 401, description = "Invalid or expired refresh token"),
        (status = 500, description = "Internal server error")
    ),
    tag = AUTH_TAG,
)]
pub async fn refresh_token(
    State(state): State<AppState>,
    audit_ctx: AuditContext,
    extract::Json(input): extract::Json<RefreshTokenInput>,
) -> Result<axum::Json<TokenPair>, AppError> {
    let mut conn = state.db_pool.acquire().await?;

    let user_id = verify_and_revoke_refresh_token(&input.refresh_token, &state.signing_key, &mut conn).await?;

    let user = User::get(user_id, &mut conn)
        .await?
        .ok_or(AppError::AuthenticationRequired)?;
    let roles = user.get_roles(&mut conn).await?;

    let token_pair = generate_token_pair(user_id, roles, &state.signing_key, &mut conn).await?;

    let _ = log_token_refresh(user_id, &audit_ctx, &mut conn).await;

    Ok(axum::Json(token_pair))
}

#[utoipa::path(
    post,
    path = "/api/auth/logout",
    request_body(content = RefreshTokenInput),
    responses(
        (status = 204, description = "Logged out successfully"),
        (status = 401, description = "Invalid refresh token"),
        (status = 500, description = "Internal server error")
    ),
    tag = AUTH_TAG,
)]
pub async fn logout(
    State(state): State<AppState>,
    audit_ctx: AuditContext,
    extract::Json(input): extract::Json<RefreshTokenInput>,
) -> Result<StatusCode, AppError> {
    let mut conn = state.db_pool.acquire().await?;

    let user_id = verify_and_revoke_refresh_token(&input.refresh_token, &state.signing_key, &mut conn).await?;
    let _ = revoke_user_access_tokens(user_id, &mut conn).await;

    info!(user_id = %user_id, "user logged out");
    let _ = log_logout(user_id, &audit_ctx, &mut conn).await;

    Ok(StatusCode::NO_CONTENT)
}

// ============================================================================
// Browser-Friendly Auth Endpoints
// ============================================================================

#[derive(Debug, Deserialize, ToSchema)]
pub struct BrowserLoginQuery {
    pub redirect_uri: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BrowserLoginResponse {
    pub success: bool,
    pub redirect_uri: Option<String>,
}

#[utoipa::path(
    post,
    path = "/api/auth/login",
    request_body(content = LoginInput),
    params(
        ("redirect_uri" = Option<String>, Query, description = "URL to redirect to after login")
    ),
    responses(
        (status = 200, description = "Login successful, cookies set"),
        (status = 302, description = "Login successful, redirecting"),
        (status = 400, description = "Invalid input"),
        (status = 401, description = "Invalid credentials"),
        (status = 429, description = "Too many login attempts"),
        (status = 500, description = "Internal server error")
    ),
    tag = AUTH_TAG,
)]
pub async fn browser_login(
    State(state): State<AppState>,
    audit_ctx: AuditContext,
    Query(query): Query<BrowserLoginQuery>,
    extract::Json(input): extract::Json<LoginInput>,
) -> Result<Response, LoginError> {
    if let Err(retry_after) = state.login_rate_limiter.check(audit_ctx.ip).await {
        warn!(ip = %audit_ctx.ip, "browser login rate limit exceeded");
        return Err(LoginError::RateLimit(RateLimitExceeded { retry_after }));
    }

    let mut conn = state.db_pool.acquire().await?;

    if let Err(msg) = Authenticator::validate_password(&input.password) {
        return Err(AppError::InputError(vec![msg]).into());
    }

    let username = input.username.clone();
    let user = match User::login(input, &mut conn).await {
        Ok(user) => user,
        Err(e) => {
            state.login_rate_limiter.record_failure(audit_ctx.ip).await;
            let failed_user_id = User::get_by_username(&username, &mut conn).await.ok().flatten().map(|u| u.id);
            warn!(username = %username, ip = %audit_ctx.ip, "browser login failed");
            let _ = log_login_failed(&username, failed_user_id, &audit_ctx, &mut conn).await;
            return Err(e.into());
        }
    };

    let roles = user.get_roles(&mut conn).await?;
    let token_pair = generate_token_pair(user.id, roles, &state.signing_key, &mut conn).await?;

    info!(user_id = %user.id, username = %user.username, "browser login successful");
    let _ = log_login_success(user.id, &audit_ctx, &mut conn).await;

    let access_cookie = build_auth_cookie(&token_pair.access_token, token_pair.expires_in);
    let refresh_cookie = build_refresh_cookie(
        &token_pair.refresh_token,
        REFRESH_TOKEN_LIFETIME,
    );

    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::SET_COOKIE,
        access_cookie.parse().unwrap(),
    );
    headers.append(
        axum::http::header::SET_COOKIE,
        refresh_cookie.parse().unwrap(),
    );

    if let Some(redirect_uri) = query.redirect_uri {
        if redirect_uri.starts_with('/') {
            headers.insert(
                axum::http::header::LOCATION,
                redirect_uri.parse().unwrap(),
            );
            return Ok((StatusCode::SEE_OTHER, headers).into_response());
        }
    }

    Ok((
        StatusCode::OK,
        headers,
        axum::Json(BrowserLoginResponse {
            success: true,
            redirect_uri: None,
        }),
    )
        .into_response())
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct BrowserLogoutQuery {
    pub redirect_uri: Option<String>,
}

#[utoipa::path(
    post,
    path = "/api/auth/browser-logout",
    params(
        ("redirect_uri" = Option<String>, Query, description = "URL to redirect to after logout")
    ),
    responses(
        (status = 200, description = "Logged out, cookies cleared"),
        (status = 302, description = "Logged out, redirecting"),
        (status = 500, description = "Internal server error")
    ),
    tag = AUTH_TAG,
)]
pub async fn browser_logout(
    State(state): State<AppState>,
    audit_ctx: AuditContext,
    headers: HeaderMap,
    Query(query): Query<BrowserLogoutQuery>,
) -> Result<Response, AppError> {
    let mut conn = state.db_pool.acquire().await?;

    let refresh_token = headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies
                .split(';')
                .map(|s| s.trim())
                .find(|s| s.starts_with("authere_refresh="))
                .map(|s| s.strip_prefix("authere_refresh=").unwrap_or(""))
        });

    if let Some(token) = refresh_token {
        if let Ok(user_id) = verify_and_revoke_refresh_token(token, &state.signing_key, &mut conn).await {
            let _ = revoke_user_access_tokens(user_id, &mut conn).await;
            info!(user_id = %user_id, "browser logout");
            let _ = log_logout(user_id, &audit_ctx, &mut conn).await;
        }
    }

    let clear_cookies = clear_auth_cookies();

    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::SET_COOKIE,
        clear_cookies[0].parse().unwrap(),
    );
    headers.append(
        axum::http::header::SET_COOKIE,
        clear_cookies[1].parse().unwrap(),
    );

    if let Some(redirect_uri) = query.redirect_uri {
        if redirect_uri.starts_with('/') {
            headers.insert(
                axum::http::header::LOCATION,
                redirect_uri.parse().unwrap(),
            );
            return Ok((StatusCode::SEE_OTHER, headers).into_response());
        }
    }

    Ok((
        StatusCode::OK,
        headers,
        axum::Json(serde_json::json!({ "success": true })),
    )
        .into_response())
}

#[utoipa::path(
    post,
    path = "/api/auth/browser-refresh",
    responses(
        (status = 200, description = "Token refreshed, new cookies set"),
        (status = 401, description = "Missing or invalid refresh token"),
        (status = 500, description = "Internal server error")
    ),
    tag = AUTH_TAG,
)]
pub async fn browser_refresh(
    State(state): State<AppState>,
    audit_ctx: AuditContext,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let mut conn = state.db_pool.acquire().await?;

    let refresh_token_str = headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies
                .split(';')
                .map(|s| s.trim())
                .find(|s| s.starts_with("authere_refresh="))
                .and_then(|s| s.strip_prefix("authere_refresh="))
                .map(|s| s.to_owned())
        })
        .ok_or(AppError::AuthenticationRequired)?;

    let user_id = verify_and_revoke_refresh_token(&refresh_token_str, &state.signing_key, &mut conn).await?;

    let user = User::get(user_id, &mut conn)
        .await?
        .ok_or(AppError::AuthenticationRequired)?;
    let roles = user.get_roles(&mut conn).await?;
    let token_pair = generate_token_pair(user_id, roles, &state.signing_key, &mut conn).await?;

    let _ = log_token_refresh(user_id, &audit_ctx, &mut conn).await;

    let access_cookie = build_auth_cookie(&token_pair.access_token, token_pair.expires_in);
    let refresh_cookie = build_refresh_cookie(
        &token_pair.refresh_token,
        REFRESH_TOKEN_LIFETIME,
    );

    let mut response_headers = HeaderMap::new();
    response_headers.insert(axum::http::header::SET_COOKIE, access_cookie.parse().unwrap());
    response_headers.append(axum::http::header::SET_COOKIE, refresh_cookie.parse().unwrap());

    Ok((StatusCode::OK, response_headers, axum::Json(serde_json::json!({ "ok": true }))).into_response())
}

// ============================================================================
// Forward Auth Endpoint
// ============================================================================

fn build_forward_auth_redirect(origin: &str, headers: &HeaderMap) -> Response {
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("https");
    let host = headers
        .get("x-forwarded-host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let uri = headers
        .get("x-forwarded-uri")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("/");

    let redirect_uri = if host.is_empty() {
        String::from("/")
    } else {
        format!("{proto}://{host}{uri}")
    };

    let location = format!(
        "{origin}/api/auth/forward-redirect?redirect_uri={}",
        urlencoding::encode(&redirect_uri)
    );

    (
        StatusCode::TEMPORARY_REDIRECT,
        [(header::LOCATION, location)],
    )
        .into_response()
}

#[utoipa::path(
    get,
    path = "/api/auth/verify",
    responses(
        (status = 200, description = "Authenticated and authorized"),
        (status = 307, description = "Not authenticated, redirect to login"),
        (status = 403, description = "Not authorized for this application"),
        (status = 500, description = "Internal server error")
    ),
    tag = AUTH_TAG,
)]
pub async fn verify_auth(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    let mut conn = state.db_pool.acquire().await.map_err(|e| {
        AppError::DbError(e).into_response()
    })?;

    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok());

    let cookie_token = headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies
                .split(';')
                .map(|s| s.trim())
                .find(|s| s.starts_with("authere_token="))
                .map(|s| s.strip_prefix("authere_token=").unwrap_or(""))
        });

    let token = match auth_header
        .and_then(|h| h.strip_prefix("Bearer "))
        .or(cookie_token)
    {
        Some(t) => t,
        None => return Err(build_forward_auth_redirect(&state.origin, &headers)),
    };

    let claims = match token::verify_access_token(token, &state.signing_key, &mut conn).await {
        Ok(c) => c,
        Err(_) => return Err(build_forward_auth_redirect(&state.origin, &headers)),
    };

    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::InternalError("Invalid user ID in token".to_string()).into_response())?;

    let user = match User::get(user_id, &mut conn).await {
        Ok(Some(u)) => u,
        _ => return Err(build_forward_auth_redirect(&state.origin, &headers)),
    };

    let host = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get("host"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let path = headers
        .get("x-forwarded-uri")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("/");

    use crate::application::Application;
    if let Some(app) = Application::find_matching(host, path, &mut conn).await.map_err(|e| e.into_response())? {
        if !app.check_access_resolved(&claims.roles, &mut conn).await.map_err(|e| e.into_response())? {
            warn!(
                user_id = %user_id,
                host = %host,
                path = %path,
                app = %app.name,
                user_roles = ?claims.roles,
                required_roles = ?app.required_roles,
                "forward auth denied: insufficient roles"
            );
            return Err(AppError::Forbidden.into_response());
        }
    }

    let response_headers = build_auth_headers(&user, &claims.roles, user.email.as_deref());

    Ok((StatusCode::OK, response_headers).into_response())
}

// ============================================================================
// Forward Auth Redirect Flow
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct ForwardRedirectQuery {
    pub redirect_uri: String,
}

#[utoipa::path(
    get,
    path = "/api/auth/forward-redirect",
    params(
        ("redirect_uri" = String, Query, description = "Full external URL to redirect to after setting cookies")
    ),
    responses(
        (status = 307, description = "Redirect to callback on target domain with forward token"),
        (status = 401, description = "Not authenticated"),
        (status = 500, description = "Internal server error")
    ),
    tag = AUTH_TAG,
)]
pub async fn forward_redirect(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ForwardRedirectQuery>,
) -> Result<Response, AppError> {
    let mut conn = state.db_pool.acquire().await?;

    let cookie_token = headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies
                .split(';')
                .map(|s| s.trim())
                .find(|s| s.starts_with("authere_token="))
                .map(|s| s.strip_prefix("authere_token=").unwrap_or(""))
        });

    let claims = match cookie_token {
        Some(t) => match token::verify_access_token(t, &state.signing_key, &mut conn).await {
            Ok(c) => c,
            Err(_) => {
                let login_url = format!(
                    "/login?redirect_uri={}",
                    urlencoding::encode(&format!(
                        "/api/auth/forward-redirect?redirect_uri={}",
                        urlencoding::encode(&query.redirect_uri)
                    ))
                );
                return Ok((
                    StatusCode::TEMPORARY_REDIRECT,
                    [(header::LOCATION, login_url)],
                ).into_response());
            }
        },
        None => {
            let login_url = format!(
                "/login?redirect_uri={}",
                urlencoding::encode(&format!(
                    "/api/auth/forward-redirect?redirect_uri={}",
                    urlencoding::encode(&query.redirect_uri)
                ))
            );
            return Ok((
                StatusCode::TEMPORARY_REDIRECT,
                [(header::LOCATION, login_url)],
            ).into_response());
        }
    };

    let parsed = url::Url::parse(&query.redirect_uri)
        .map_err(|_| AppError::InputError(vec!["Invalid redirect_uri".into()]))?;
    let target_host = parsed.host_str()
        .ok_or_else(|| AppError::InputError(vec!["redirect_uri has no host".into()]))?
        .to_string();
    let target_scheme = parsed.scheme();
    let target_path = parsed.path();

    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::InternalError("Invalid user ID in token".into()))?;

    let forward_token = token::generate_forward_token(
        user_id,
        claims.roles,
        &target_host,
        &state.signing_key,
    )?;

    let callback_url = format!(
        "{target_scheme}://{target_host}/.authere/callback?token={}&redirect_uri={}",
        urlencoding::encode(&forward_token),
        urlencoding::encode(target_path),
    );

    Ok((
        StatusCode::TEMPORARY_REDIRECT,
        [(header::LOCATION, callback_url)],
    )
        .into_response())
}

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    pub token: String,
    pub redirect_uri: Option<String>,
}

#[utoipa::path(
    get,
    path = "/.authere/callback",
    params(
        ("token" = String, Query, description = "Forward auth token"),
        ("redirect_uri" = Option<String>, Query, description = "Path to redirect to after setting cookies")
    ),
    responses(
        (status = 307, description = "Cookies set, redirecting to final destination"),
        (status = 401, description = "Invalid or expired token"),
        (status = 403, description = "Token host mismatch"),
        (status = 500, description = "Internal server error")
    ),
    tag = AUTH_TAG,
)]
pub async fn forward_auth_callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> Result<Response, AppError> {
    let request_host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let claims = token::verify_forward_token(&query.token, request_host, &state.signing_key)?;

    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::InternalError("Invalid user ID in token".into()))?;

    let mut conn = state.db_pool.acquire().await?;

    let user = User::get(user_id, &mut conn)
        .await?
        .ok_or(AppError::AuthenticationRequired)?;
    let roles = user.get_roles(&mut conn).await?;

    let token_pair = generate_token_pair(user_id, roles, &state.signing_key, &mut conn).await?;

    let access_cookie = build_auth_cookie(&token_pair.access_token, token_pair.expires_in);
    let refresh_cookie = build_refresh_cookie(&token_pair.refresh_token, REFRESH_TOKEN_LIFETIME);

    let redirect_path = query.redirect_uri
        .filter(|p| p.starts_with('/'))
        .unwrap_or_else(|| "/".into());

    let mut resp_headers = HeaderMap::new();
    resp_headers.insert(header::SET_COOKIE, access_cookie.parse().unwrap());
    resp_headers.append(header::SET_COOKIE, refresh_cookie.parse().unwrap());
    resp_headers.insert(header::LOCATION, redirect_path.parse().unwrap());

    Ok((StatusCode::TEMPORARY_REDIRECT, resp_headers).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_auth_headers() {
        let user = User {
            id: Uuid::nil(),
            username: "testuser".into(),
            name: "Test User".into(),
            email: Some("test@example.com".into()),
        };
        let roles = vec!["admin".into(), "user".into()];

        let headers = build_auth_headers(&user, &roles, user.email.as_deref());

        assert_eq!(
            headers.get("x-auth-user").unwrap(),
            &Uuid::nil().to_string()
        );
        assert_eq!(headers.get("x-auth-username").unwrap(), "testuser");
        assert_eq!(headers.get("x-auth-roles").unwrap(), "admin,user");
        assert_eq!(headers.get("x-auth-email").unwrap(), "test@example.com");
    }

    #[test]
    fn test_build_auth_headers_no_email() {
        let user = User {
            id: Uuid::nil(),
            username: "testuser".into(),
            name: "Test User".into(),
            email: None,
        };
        let roles = vec!["user".into()];

        let headers = build_auth_headers(&user, &roles, None);

        assert!(headers.get("x-auth-email").is_none());
        assert_eq!(headers.get("x-auth-username").unwrap(), "testuser");
        assert_eq!(headers.get("x-auth-roles").unwrap(), "user");
    }

    #[test]
    fn test_build_auth_headers_empty_roles() {
        let user = User {
            id: Uuid::nil(),
            username: "testuser".into(),
            name: "Test".into(),
            email: None,
        };

        let headers = build_auth_headers(&user, &[], None);
        assert_eq!(headers.get("x-auth-roles").unwrap(), "");
    }

    fn extract_location(resp: &Response) -> &str {
        resp.headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
    }

    #[test]
    fn forward_auth_redirect_builds_full_url() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        headers.insert("x-forwarded-host", "flood.example.com".parse().unwrap());
        headers.insert("x-forwarded-uri", "/some/path".parse().unwrap());

        let resp = build_forward_auth_redirect("https://auth.example.com", &headers);

        assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            extract_location(&resp),
            "https://auth.example.com/api/auth/forward-redirect?redirect_uri=https%3A%2F%2Fflood.example.com%2Fsome%2Fpath"
        );
    }

    #[test]
    fn forward_auth_redirect_defaults_to_slash_when_no_host() {
        let headers = HeaderMap::new();
        let resp = build_forward_auth_redirect("https://auth.example.com", &headers);

        assert_eq!(
            extract_location(&resp),
            "https://auth.example.com/api/auth/forward-redirect?redirect_uri=%2F"
        );
    }

    #[test]
    fn forward_auth_redirect_defaults_proto_to_https() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-host", "app.example.com".parse().unwrap());

        let resp = build_forward_auth_redirect("https://auth.example.com", &headers);

        assert!(extract_location(&resp).contains("https%3A%2F%2Fapp.example.com"));
    }

    #[test]
    fn forward_auth_redirect_defaults_uri_to_slash() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        headers.insert("x-forwarded-host", "app.example.com".parse().unwrap());

        let resp = build_forward_auth_redirect("https://auth.example.com", &headers);

        assert_eq!(
            extract_location(&resp),
            "https://auth.example.com/api/auth/forward-redirect?redirect_uri=https%3A%2F%2Fapp.example.com%2F"
        );
    }
}

use axum::extract::{self, Query, State};
use axum::http::header::{self, HeaderMap, HeaderName, HeaderValue};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::AppState;
use crate::application::Application;
use crate::audit::{audit, AuditContext, AuditEventType, log_login_failed};
use crate::db::DbEntity;
use crate::errors::AppError;
use crate::handlers::{LoginError, build_auth_cookie, build_refresh_cookie, clear_auth_cookies};
use crate::rate_limit::RateLimitExceeded;
use crate::user::auth::Authenticator;
use crate::user::auth::token::{self, TokenPair, generate_token_pair, verify_and_revoke_refresh_token, revoke_user_access_tokens};
use crate::user::auth::totp::{self, UserTotp};
use crate::user::{LoginInput, User};

/// Enforce MFA for users who have activated TOTP. Call AFTER successful password check.
/// Returns Ok(()) if the user has no MFA, or if the provided code matches. Returns
/// `LoginError::MfaRequired` when no code is provided and `MfaInvalid` when the code is wrong.
async fn enforce_mfa(
    user_id: uuid::Uuid,
    totp_code: Option<&str>,
    conn: &mut sqlx::SqliteConnection,
) -> Result<(), LoginError> {
    let Some(totp_row) = UserTotp::get(user_id, conn).await.map_err(LoginError::App)? else {
        return Ok(());
    };
    if !totp_row.is_activated() {
        return Ok(());
    }
    let Some(code) = totp_code.map(|c| c.trim()).filter(|c| !c.is_empty()) else {
        return Err(LoginError::MfaRequired);
    };

    let secret = totp::decrypt_secret(&totp_row.secret_encrypted).map_err(LoginError::App)?;
    let now = totp::now_epoch();
    if let Some(step) = totp::verify_code(&secret, code, now, totp_row.last_used_step) {
        UserTotp::record_step(user_id, step, conn).await.map_err(LoginError::App)?;
        return Ok(());
    }
    // Fall back to recovery codes. Consumption is atomic; a valid unused code is accepted once.
    if totp::consume_recovery_code(user_id, code, conn).await.map_err(LoginError::App)? {
        return Ok(());
    }
    Err(LoginError::MfaInvalid)
}

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
            totp_code: None,
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
    let totp_code = input.totp_code.clone();
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

    match enforce_mfa(user.id, totp_code.as_deref(), &mut conn).await {
        Ok(()) => {}
        Err(LoginError::MfaRequired) => return Err(LoginError::MfaRequired),
        Err(e) => {
            state.login_rate_limiter.record_failure(audit_ctx.ip).await;
            warn!(user_id = %user.id, username = %username, ip = %audit_ctx.ip, "login failed: bad totp");
            let _ = log_login_failed(&username, Some(user.id), &audit_ctx, &mut conn).await;
            return Err(e);
        }
    }

    let roles = user.get_roles(&mut conn).await?;
    let token_pair = generate_token_pair(user.id, roles, &state.signing_key, &mut conn).await?;

    info!(user_id = %user.id, username = %user.username, "login successful");
    let _ = audit(AuditEventType::LoginSuccess).user(user.id).ctx(&audit_ctx).save(&mut conn).await;

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

    let _ = audit(AuditEventType::TokenRefresh).user(user_id).ctx(&audit_ctx).save(&mut conn).await;

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
    let _ = audit(AuditEventType::Logout).user(user_id).ctx(&audit_ctx).save(&mut conn).await;

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
    let totp_code = input.totp_code.clone();
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

    match enforce_mfa(user.id, totp_code.as_deref(), &mut conn).await {
        Ok(()) => {}
        Err(LoginError::MfaRequired) => return Err(LoginError::MfaRequired),
        Err(e) => {
            state.login_rate_limiter.record_failure(audit_ctx.ip).await;
            warn!(user_id = %user.id, username = %username, ip = %audit_ctx.ip, "browser login failed: bad totp");
            let _ = log_login_failed(&username, Some(user.id), &audit_ctx, &mut conn).await;
            return Err(e);
        }
    }

    let roles = user.get_roles(&mut conn).await?;
    let token_pair = generate_token_pair(user.id, roles, &state.signing_key, &mut conn).await?;

    info!(user_id = %user.id, username = %user.username, "browser login successful");
    let _ = audit(AuditEventType::LoginSuccess).user(user.id).ctx(&audit_ctx).save(&mut conn).await;

    let access_cookie = build_auth_cookie(&token_pair.access_token, token_pair.expires_in);
    let refresh_cookie = build_refresh_cookie(
        &token_pair.refresh_token,
        token_pair.refresh_expires_in,
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
            let _ = audit(AuditEventType::Logout).user(user_id).ctx(&audit_ctx).save(&mut conn).await;
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

    let _ = audit(AuditEventType::TokenRefresh).user(user_id).ctx(&audit_ctx).save(&mut conn).await;

    let access_cookie = build_auth_cookie(&token_pair.access_token, token_pair.expires_in);
    let refresh_cookie = build_refresh_cookie(
        &token_pair.refresh_token,
        token_pair.refresh_expires_in,
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

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Render a styled HTML 403 page for forward-auth denials. The body is shown to humans
/// by the reverse proxy when verify_auth returns 403, so it gets the same dark/dotgrid
/// vibe as the login page rather than plain text.
fn build_forward_auth_denied_html(
    origin: &str,
    headers: &HeaderMap,
    app_name: Option<&str>,
    required_roles: &[String],
) -> Response {
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

    let switch_user_url = if host.is_empty() {
        format!("{origin}/login")
    } else {
        let target = format!("{proto}://{host}{uri}");
        format!(
            "{origin}/api/auth/forward-redirect?redirect_uri={}",
            urlencoding::encode(&target)
        )
    };
    let switch_user_url = html_escape(&switch_user_url);

    let app_block = match app_name {
        Some(name) if !name.is_empty() => format!(
            r#"<div class="row"><span class="label">Application</span><span class="value">{}</span></div>"#,
            html_escape(name)
        ),
        _ => String::new(),
    };

    let roles_block = if required_roles.is_empty() {
        String::new()
    } else {
        let chips: String = required_roles
            .iter()
            .map(|r| format!(r#"<span class="chip">{}</span>"#, html_escape(r)))
            .collect::<Vec<_>>()
            .join("");
        format!(
            r#"<div class="row"><span class="label">Required roles</span><span class="value chips">{chips}</span></div>"#
        )
    };

    let details = if app_block.is_empty() && roles_block.is_empty() {
        String::new()
    } else {
        format!(r#"<div class="details">{app_block}{roles_block}</div>"#)
    };

    let body = format!(
        r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Access denied</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  html, body {{ height: 100%; }}
  body {{
    background: #05080f;
    color: #f4f6fa;
    font-family: 'IBM Plex Sans', system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
    font-size: 14px;
    line-height: 1.5;
    -webkit-font-smoothing: antialiased;
    background-image: radial-gradient(circle, rgba(255,255,255,0.04) 1px, transparent 1px);
    background-size: 24px 24px;
  }}
  .wrap {{
    min-height: 100%;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 32px;
  }}
  .card {{
    width: 100%;
    max-width: 440px;
    background: #0a0f1c;
    border: 1px solid rgba(255,255,255,0.10);
    border-radius: 2px;
    padding: 32px;
    display: flex;
    flex-direction: column;
    gap: 24px;
  }}
  @media (max-width: 639.98px) {{
    .wrap {{ padding: 16px; }}
    .card {{ padding: 24px 16px; }}
  }}
  .header {{ display: flex; flex-direction: column; gap: 8px; }}
  .logo {{
    display: flex;
    align-items: center;
    gap: 8px;
    color: #f4f6fa;
    margin-bottom: 8px;
    font-size: 15px;
    font-weight: 600;
  }}
  h1 {{
    font-size: 18px;
    line-height: 1.3;
    letter-spacing: -0.005em;
    font-weight: 600;
    color: #f4f6fa;
  }}
  .subtle {{ font-size: 13px; line-height: 1.45; color: #b4bcd0; }}
  .alert {{
    display: flex;
    align-items: center;
    gap: 8px;
    color: #ef4444;
    background: #2d0a0a;
    border: 1px solid rgba(239,68,68,0.2);
    border-radius: 2px;
    padding: 8px 12px;
    font-size: 13px;
  }}
  .alert::before {{
    content: "";
    width: 14px;
    height: 14px;
    flex: 0 0 14px;
    background: #ef4444;
    -webkit-mask: url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'><path fill='black' d='M7.001 2a1 1 0 0 1 1.998 0l-.25 7a.75.75 0 0 1-1.498 0L7.001 2zm.999 12a1.25 1.25 0 1 1 0-2.5 1.25 1.25 0 0 1 0 2.5z'/></svg>") center/contain no-repeat;
            mask: url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'><path fill='black' d='M7.001 2a1 1 0 0 1 1.998 0l-.25 7a.75.75 0 0 1-1.498 0L7.001 2zm.999 12a1.25 1.25 0 1 1 0-2.5 1.25 1.25 0 0 1 0 2.5z'/></svg>") center/contain no-repeat;
  }}
  .details {{
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding: 12px;
    border: 1px solid rgba(255,255,255,0.06);
    border-radius: 2px;
    background: #0f1524;
  }}
  .row {{ display: flex; flex-direction: column; gap: 4px; }}
  .label {{
    font-family: 'IBM Plex Mono', ui-monospace, monospace;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: #8390ad;
  }}
  .value {{ color: #dce1ed; font-size: 13px; word-break: break-word; }}
  .chips {{ display: flex; flex-wrap: wrap; gap: 4px; }}
  .chip {{
    display: inline-flex;
    align-items: center;
    padding: 2px 8px;
    border: 1px solid rgba(255,255,255,0.10);
    border-radius: 2px;
    background: #141b2d;
    font-family: 'IBM Plex Mono', ui-monospace, monospace;
    font-size: 12px;
    color: #dce1ed;
  }}
  .actions {{ display: flex; flex-direction: column; gap: 8px; }}
  .btn {{
    display: inline-flex;
    align-items: center;
    justify-content: center;
    height: 40px;
    padding: 0 16px;
    border-radius: 2px;
    font-size: 14px;
    font-weight: 500;
    text-decoration: none;
    border: 1px solid transparent;
    cursor: pointer;
    transition: background-color 140ms cubic-bezier(0.2, 0, 0, 1);
  }}
  .btn-primary {{ background: #3b82f6; color: #ffffff; }}
  .btn-primary:hover {{ background: #2563eb; }}
  .btn-ghost {{
    background: transparent;
    color: #dce1ed;
    border-color: rgba(255,255,255,0.10);
  }}
  .btn-ghost:hover {{ background: #141b2d; }}
</style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <div class="header">
        <div class="logo">
          <svg width="28" height="28" viewBox="0 0 28 28" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
            <rect width="28" height="28" rx="4" fill="#3B82F6" fill-opacity="0.15"/>
            <path d="M14 5L21 9.5v9L14 23l-7-4.5v-9L14 5z" stroke="#3B82F6" stroke-width="1.5" stroke-linejoin="round" fill="none"/>
            <circle cx="14" cy="14" r="2.5" fill="#3B82F6"/>
          </svg>
          <span>authere</span>
        </div>
        <h1>Access denied</h1>
        <p class="subtle">You're signed in, but your account doesn't have permission to view this page.</p>
      </div>

      <div class="alert" role="alert">Your roles don't grant access to this application.</div>

      {details}

      <div class="actions">
        <a class="btn btn-primary" href="{switch_user_url}">Sign in as a different user</a>
        <a class="btn btn-ghost" href="javascript:history.back()">Go back</a>
      </div>
    </div>
  </div>
</body>
</html>
"##
    );

    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .body(axum::body::Body::from(body))
        .unwrap()
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
            return Err(build_forward_auth_denied_html(
                &state.origin,
                &headers,
                Some(&app.name),
                &app.required_roles,
            ));
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
    let refresh_cookie = build_refresh_cookie(&token_pair.refresh_token, token_pair.refresh_expires_in);

    let redirect_path = query.redirect_uri
        .filter(|p| p.starts_with('/'))
        .unwrap_or_else(|| "/".into());

    let mut resp_headers = HeaderMap::new();
    resp_headers.insert(header::SET_COOKIE, access_cookie.parse().unwrap());
    resp_headers.append(header::SET_COOKIE, refresh_cookie.parse().unwrap());
    resp_headers.insert(header::LOCATION, redirect_path.parse().unwrap());

    Ok((StatusCode::TEMPORARY_REDIRECT, resp_headers).into_response())
}

#[derive(Debug, Deserialize)]
pub struct ForwardAppQuery {
    /// Full external URL the user is trying to reach (the one originally
    /// passed to `/api/auth/forward-redirect`).
    pub redirect_uri: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ForwardAppResponse {
    /// Display name of the matched forward_auth application.
    pub name: String,
}

/// Look up the forward_auth application that owns the given URL so the login
/// page can show "Sign in to continue to {appName}". Public on purpose — the
/// host pattern is just a domain the caller already knows.
#[utoipa::path(
    get,
    path = "/api/auth/forward-app",
    params(
        ("redirect_uri" = String, Query, description = "Full external URL the user is trying to reach")
    ),
    responses(
        (status = 200, description = "Matching forward_auth application", body = ForwardAppResponse),
        (status = 400, description = "redirect_uri is malformed"),
        (status = 404, description = "No forward_auth application matches"),
        (status = 500, description = "Internal server error")
    ),
    tag = AUTH_TAG,
)]
pub async fn lookup_forward_app(
    State(state): State<AppState>,
    Query(query): Query<ForwardAppQuery>,
) -> Result<axum::Json<ForwardAppResponse>, AppError> {
    let parsed = url::Url::parse(&query.redirect_uri)
        .map_err(|_| AppError::InputError(vec!["Invalid redirect_uri".into()]))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| AppError::InputError(vec!["redirect_uri has no host".into()]))?;
    let path = parsed.path();

    let mut conn = state.db_pool.acquire().await?;
    match Application::find_matching(host, path, &mut conn).await? {
        Some(app) => Ok(axum::Json(ForwardAppResponse { name: app.name })),
        None => Err(AppError::NotFound),
    }
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
            active: true,
            created_at: 0,
            updated_at: 0,
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
            active: true,
            created_at: 0,
            updated_at: 0,
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
            active: true,
            created_at: 0,
            updated_at: 0,
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

    #[test]
    fn html_escape_replaces_special_chars() {
        assert_eq!(
            html_escape(r#"<script>alert("x&y's")</script>"#),
            "&lt;script&gt;alert(&quot;x&amp;y&#39;s&quot;)&lt;/script&gt;"
        );
    }

    async fn collect_body(resp: Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn forward_auth_denied_html_returns_styled_403() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        headers.insert("x-forwarded-host", "app.example.com".parse().unwrap());
        headers.insert("x-forwarded-uri", "/dashboard".parse().unwrap());

        let resp = build_forward_auth_denied_html(
            "https://auth.example.com",
            &headers,
            Some("Production Dashboard"),
            &["admin".to_string(), "ops".to_string()],
        );

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8"
        );

        let body = collect_body(resp).await;
        assert!(body.contains("<title>Access denied</title>"));
        assert!(body.contains("Access denied"));
        assert!(body.contains("Production Dashboard"));
        assert!(body.contains(r#"<span class="chip">admin</span>"#));
        assert!(body.contains(r#"<span class="chip">ops</span>"#));
        assert!(body.contains(
            "https://auth.example.com/api/auth/forward-redirect?redirect_uri=https%3A%2F%2Fapp.example.com%2Fdashboard"
        ));
    }

    #[tokio::test]
    async fn forward_auth_denied_html_escapes_app_name_and_roles() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-host", "app.example.com".parse().unwrap());

        let resp = build_forward_auth_denied_html(
            "https://auth.example.com",
            &headers,
            Some("<evil> & co"),
            &["<role>".to_string()],
        );

        let body = collect_body(resp).await;
        assert!(body.contains("&lt;evil&gt; &amp; co"));
        assert!(body.contains("&lt;role&gt;"));
        assert!(!body.contains("<evil>"));
    }

    #[tokio::test]
    async fn forward_auth_denied_html_omits_details_when_unknown() {
        let headers = HeaderMap::new();

        let resp = build_forward_auth_denied_html(
            "https://auth.example.com",
            &headers,
            None,
            &[],
        );

        let body = collect_body(resp).await;
        assert!(!body.contains(r#"class="details""#));
        // Falls back to plain /login when no forwarded host is present.
        assert!(body.contains(r#"href="https://auth.example.com/login""#));
    }
}

//! OpenID Connect provider endpoints.
//!
//! Surface area:
//!   - `GET  /.well-known/openid-configuration` — Discovery (OIDC Discovery §3)
//!   - `GET  /.well-known/jwks.json`             — JWKS for id_token verification
//!   - `GET  /oauth/authorize`                   — Authorization endpoint (code flow + PKCE)
//!   - `POST /oauth/token`                       — Token endpoint (code exchange)
//!   - `GET  /oauth/userinfo`                    — UserInfo endpoint
//!   - `GET  /oauth/end_session`                 — RP-initiated logout
//!
//! The authorize handler reuses the existing Authere session cookie for login: if the user
//! is already signed in, the code is issued inline; otherwise the browser is redirected to
//! `/login` with a `redirect_uri` that bounces back to this handler once the session cookie
//! is set.

use axum::extract::{Form, Query, State};
use axum::http::Uri;
use axum::http::header::{self, AUTHORIZATION, LOCATION, SET_COOKIE, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, warn};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::AppState;
use crate::application::{AppType, Application};
use crate::audit::{AuditContext, AuditEventType, audit};
use crate::db::DbEntity;
use crate::handlers::{
    AUTH_COOKIE_NAME, REFRESH_COOKIE_NAME, build_auth_cookie, build_refresh_cookie,
    clear_auth_cookies,
};
use crate::oidc::codes;
use crate::oidc::jwks::build_jwks;
use crate::oidc::token::{
    self, SCOPE_OPENID, TokenResponse, mint_token_pair, parse_scope, scope_contains,
    verify_oidc_access_token,
};
use crate::rate_limit::RateLimitExceeded;
use crate::user::User;
use crate::user::auth::token::{
    TokenPair, revoke_all_user_tokens, rotate_browser_token_pair, verify_access_token,
    verify_user_session,
};

const OIDC_TAG: &str = "oidc";

/// OAuth2/OIDC-spec error shapes. Rendered either as 400 JSON or as a redirect back to the
/// RP with `error=` + `error_description=` query params (authorization endpoint only).
#[derive(Debug, Clone)]
pub enum OAuthError {
    InvalidRequest(&'static str),
    InvalidClient,
    InvalidGrant(&'static str),
    UnauthorizedClient,
    UnsupportedResponseType,
    UnsupportedGrantType,
    InvalidScope,
    AccessDenied,
    LoginRequired,
    ServerError,
}

impl OAuthError {
    fn code(&self) -> &'static str {
        match self {
            OAuthError::InvalidRequest(_) => "invalid_request",
            OAuthError::InvalidClient => "invalid_client",
            OAuthError::InvalidGrant(_) => "invalid_grant",
            OAuthError::UnauthorizedClient => "unauthorized_client",
            OAuthError::UnsupportedResponseType => "unsupported_response_type",
            OAuthError::UnsupportedGrantType => "unsupported_grant_type",
            OAuthError::InvalidScope => "invalid_scope",
            OAuthError::AccessDenied => "access_denied",
            OAuthError::LoginRequired => "login_required",
            OAuthError::ServerError => "server_error",
        }
    }

    fn description(&self) -> Option<&'static str> {
        match self {
            OAuthError::InvalidRequest(m) | OAuthError::InvalidGrant(m) => Some(m),
            _ => None,
        }
    }

    fn token_endpoint_status(&self) -> StatusCode {
        match self {
            OAuthError::InvalidClient => StatusCode::UNAUTHORIZED,
            OAuthError::ServerError => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::BAD_REQUEST,
        }
    }
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        let status = self.token_endpoint_status();
        let mut body = json!({ "error": self.code() });
        if let Some(desc) = self.description() {
            body["error_description"] = json!(desc);
        }
        let mut resp = (status, axum::Json(body)).into_response();
        resp.headers_mut()
            .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
        if matches!(self, OAuthError::InvalidClient) {
            resp.headers_mut()
                .insert(WWW_AUTHENTICATE, "Basic realm=\"oidc\"".parse().unwrap());
        }
        resp
    }
}

/// Extract the host-bound Authere session cookie from the request.
fn extract_session_cookie(headers: &HeaderMap) -> Option<String> {
    extract_cookie(headers, AUTH_COOKIE_NAME)
}

fn extract_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let mut values = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|value| value.trim().split_once('='))
        .filter_map(|(key, value)| (key == name).then_some(value));
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    Some(value.to_string())
}

async fn resolve_browser_session(
    state: &AppState,
    headers: &HeaderMap,
    conn: &mut sqlx::SqliteConnection,
    renewed: &mut Option<TokenPair>,
) -> Result<Option<crate::user::auth::token::Claims>, crate::errors::AppError> {
    use crate::errors::AppError;
    if let Some(access) = extract_session_cookie(headers) {
        match verify_access_token(&access, &state.signing_key, conn).await {
            Ok(claims) => return Ok(Some(claims)),
            Err(AppError::AuthenticationRequired) => {}
            Err(error) => return Err(error),
        }
    }
    if let Some(refresh) = extract_cookie(headers, REFRESH_COOKIE_NAME) {
        match rotate_browser_token_pair(&refresh, &state.signing_key, conn).await {
            Ok(pair) => {
                let claims =
                    verify_access_token(&pair.access_token, &state.signing_key, conn).await?;
                *renewed = Some(pair);
                return Ok(Some(claims));
            }
            Err(AppError::AuthenticationRequired) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(None)
}

fn append_session_cookies(response: &mut Response, pair: &TokenPair) {
    response.headers_mut().append(
        SET_COOKIE,
        build_auth_cookie(&pair.access_token, pair.expires_in)
            .parse()
            .unwrap(),
    );
    response.headers_mut().append(
        SET_COOKIE,
        build_refresh_cookie(&pair.refresh_token, pair.refresh_expires_in)
            .parse()
            .unwrap(),
    );
}

// ============================================================================
// Discovery + JWKS
// ============================================================================

#[derive(Debug, Serialize, ToSchema)]
pub struct DiscoveryDocument {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    end_session_endpoint: String,
    jwks_uri: String,
    response_types_supported: Vec<String>,
    subject_types_supported: Vec<String>,
    id_token_signing_alg_values_supported: Vec<String>,
    scopes_supported: Vec<String>,
    token_endpoint_auth_methods_supported: Vec<String>,
    grant_types_supported: Vec<String>,
    code_challenge_methods_supported: Vec<String>,
    claims_supported: Vec<String>,
}

fn build_discovery(origin: &str) -> DiscoveryDocument {
    DiscoveryDocument {
        issuer: origin.to_string(),
        authorization_endpoint: format!("{origin}/oauth/authorize"),
        token_endpoint: format!("{origin}/oauth/token"),
        userinfo_endpoint: format!("{origin}/oauth/userinfo"),
        end_session_endpoint: format!("{origin}/oauth/end_session"),
        jwks_uri: format!("{origin}/.well-known/jwks.json"),
        response_types_supported: vec!["code".into()],
        subject_types_supported: vec!["public".into()],
        id_token_signing_alg_values_supported: vec!["EdDSA".into()],
        scopes_supported: vec![
            "openid".into(),
            "profile".into(),
            "email".into(),
            "roles".into(),
        ],
        token_endpoint_auth_methods_supported: vec![
            "client_secret_basic".into(),
            "client_secret_post".into(),
            "none".into(),
        ],
        grant_types_supported: vec!["authorization_code".into()],
        code_challenge_methods_supported: vec!["S256".into()],
        claims_supported: vec![
            "sub".into(),
            "iss".into(),
            "aud".into(),
            "exp".into(),
            "iat".into(),
            "auth_time".into(),
            "nonce".into(),
            "name".into(),
            "preferred_username".into(),
            "updated_at".into(),
            "email".into(),
            "roles".into(),
        ],
    }
}

#[utoipa::path(
    get,
    path = "/.well-known/openid-configuration",
    responses(
        (status = 200, description = "OIDC discovery document", body = DiscoveryDocument)
    ),
    tag = OIDC_TAG,
)]
pub async fn discovery(State(state): State<AppState>) -> axum::Json<DiscoveryDocument> {
    axum::Json(build_discovery(&state.origin))
}

#[utoipa::path(
    get,
    path = "/.well-known/jwks.json",
    responses(
        (status = 200, description = "JWKS for id_token verification")
    ),
    tag = OIDC_TAG,
)]
pub async fn jwks(State(state): State<AppState>) -> axum::Json<serde_json::Value> {
    let set = build_jwks(&state.signing_key, &state.signing_kid);
    axum::Json(serde_json::to_value(set).unwrap_or(json!({"keys": []})))
}

// ============================================================================
// Authorization endpoint
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    pub response_type: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub prompt: Option<String>,
    pub max_age: Option<String>,
}

/// Append query parameters to a base URI. Uses `?` if none present, else `&`. This keeps us
/// independent of whether the RP's registered redirect_uri already has query params.
fn append_query(base: &str, params: &[(&str, &str)]) -> String {
    let mut out = String::from(base);
    let mut sep = if out.contains('?') { '&' } else { '?' };
    for (k, v) in params {
        out.push(sep);
        out.push_str(&urlencoding::encode(k));
        out.push('=');
        out.push_str(&urlencoding::encode(v));
        sep = '&';
    }
    out
}

fn redirect(status: StatusCode, location: String) -> Response {
    (
        status,
        [
            (LOCATION, location),
            (header::CACHE_CONTROL, "no-store".to_string()),
            (header::REFERRER_POLICY, "no-referrer".to_string()),
        ],
    )
        .into_response()
}

fn authorize_error_redirect(
    redirect_uri: &str,
    state_param: Option<&str>,
    err: &OAuthError,
) -> Response {
    let code = err.code();
    let mut params: Vec<(&str, &str)> = vec![("error", code)];
    if let Some(desc) = err.description() {
        params.push(("error_description", desc));
    }
    if let Some(st) = state_param {
        params.push(("state", st));
    }
    redirect(StatusCode::FOUND, append_query(redirect_uri, &params))
}

#[utoipa::path(
    get,
    path = "/oauth/authorize",
    responses(
        (status = 302, description = "Redirect to RP with code (or back to /login if unauthenticated)"),
        (status = 400, description = "Invalid request (no trusted redirect_uri to bounce the error)")
    ),
    tag = OIDC_TAG,
)]
pub async fn authorize(
    State(state): State<AppState>,
    audit_ctx: AuditContext,
    headers: HeaderMap,
    uri: Uri,
    Query(q): Query<AuthorizeQuery>,
) -> Response {
    let mut renewed = None;
    let mut response = authorize_impl(state, audit_ctx, headers, uri, q, &mut renewed).await;
    // A central session remains usable for its configured lifetime even when its short
    // access token expired between visits to an OIDC application.
    if let Some(pair) = renewed {
        append_session_cookies(&mut response, &pair);
    }
    response
}

async fn authorize_impl(
    state: AppState,
    audit_ctx: AuditContext,
    headers: HeaderMap,
    uri: Uri,
    q: AuthorizeQuery,
    renewed: &mut Option<TokenPair>,
) -> Response {
    let mut conn = match state.db_pool.acquire().await {
        Ok(c) => c,
        Err(_) => return OAuthError::ServerError.into_response(),
    };

    // Step 1: validate client + redirect_uri before we're willing to redirect anywhere.
    let client_id = match q.client_id.as_deref() {
        Some(s) if !s.is_empty() => s,
        _ => return OAuthError::InvalidRequest("missing client_id").into_response(),
    };
    let presented_redirect = match q.redirect_uri.as_deref() {
        Some(s) if !s.is_empty() => s,
        _ => return OAuthError::InvalidRequest("missing redirect_uri").into_response(),
    };
    let app = match Application::get_by_oidc_client_id(client_id, &mut conn).await {
        Ok(Some(a)) => a,
        Ok(None) => return OAuthError::InvalidClient.into_response(),
        Err(_) => return OAuthError::ServerError.into_response(),
    };
    if !app.enabled || app.app_type != AppType::Oidc {
        return OAuthError::UnauthorizedClient.into_response();
    }
    if !app.validate_redirect_uri(presented_redirect) {
        // Never bounce to an unregistered URI — the spec requires us to render the error
        // directly (OAuth2 §4.1.2.1 / §3.1.2.4).
        return OAuthError::InvalidRequest("redirect_uri not registered").into_response();
    }

    // From here on, errors that are the RP's fault get bounced back to the registered URI.
    let state_param = q.state.as_deref();

    if q.response_type.as_deref() != Some("code") {
        return authorize_error_redirect(
            presented_redirect,
            state_param,
            &OAuthError::UnsupportedResponseType,
        );
    }

    // Do not silently satisfy a reauthentication request with an existing session. The
    // login UI does not yet provide a reauthentication/consent flow for these parameters.
    let prompt_none = q
        .prompt
        .as_deref()
        .is_some_and(|prompt| prompt.split_whitespace().eq(["none"]));
    if q.max_age.is_some()
        || q.prompt
            .as_deref()
            .is_some_and(|prompt| !prompt.is_empty() && !prompt_none)
    {
        return authorize_error_redirect(
            presented_redirect,
            state_param,
            &OAuthError::InvalidRequest("requested reauthentication or consent is not supported"),
        );
    }

    let scope = parse_scope(q.scope.as_deref().unwrap_or(""));
    if !scope_contains(&scope, SCOPE_OPENID)
        || scope
            .iter()
            .any(|s| !matches!(s.as_str(), "openid" | "profile" | "email" | "roles"))
    {
        return authorize_error_redirect(
            presented_redirect,
            state_param,
            &OAuthError::InvalidScope,
        );
    }

    let challenge = match q.code_challenge.as_deref() {
        Some(s) if !s.is_empty() => s,
        _ => {
            return authorize_error_redirect(
                presented_redirect,
                state_param,
                &OAuthError::InvalidRequest("missing code_challenge (PKCE required)"),
            );
        }
    };
    let method = q.code_challenge_method.as_deref().unwrap_or("plain");
    if method != "S256" {
        return authorize_error_redirect(
            presented_redirect,
            state_param,
            &OAuthError::InvalidRequest("code_challenge_method must be S256"),
        );
    }
    if challenge.len() != 43
        || !challenge
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        || base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(challenge)
            .is_err()
    {
        return authorize_error_redirect(
            presented_redirect,
            state_param,
            &OAuthError::InvalidRequest("invalid S256 code_challenge"),
        );
    }

    // Step 2: check the user's Authere session. Missing/expired -> bounce through /login.
    let needs_login = || {
        if prompt_none {
            authorize_error_redirect(presented_redirect, state_param, &OAuthError::LoginRequired)
        } else {
            login_redirect(&uri)
        }
    };
    let claims = match resolve_browser_session(&state, &headers, &mut conn, renewed).await {
        Ok(Some(claims)) => claims,
        Ok(None) => return needs_login(),
        Err(_) => return OAuthError::ServerError.into_response(),
    };

    let user_id = match Uuid::parse_str(&claims.sub) {
        Ok(u) => u,
        Err(_) => {
            return authorize_error_redirect(
                presented_redirect,
                state_param,
                &OAuthError::ServerError,
            );
        }
    };

    // Step 3: use current roles so removing access takes effect before the session expires.
    let user = match User::get(user_id, &mut conn).await {
        Ok(Some(user)) if user.active => user,
        Ok(_) => return needs_login(),
        Err(_) => return OAuthError::ServerError.into_response(),
    };
    let roles = match user.get_roles(&mut conn).await {
        Ok(roles) => roles,
        Err(_) => return OAuthError::ServerError.into_response(),
    };
    match app.check_access_resolved(&roles, &mut conn).await {
        Ok(true) => {}
        Ok(false) => {
            warn!(
                user_id = %user_id,
                client_id = %client_id,
                "oidc authorize denied: insufficient roles"
            );
            let _ = audit(AuditEventType::OidcAuthorizeDenied)
                .user(user_id)
                .ctx(&audit_ctx)
                .details(json!({ "client_id": client_id, "reason": "insufficient_roles" }))
                .save(&mut conn)
                .await;
            return authorize_error_redirect(
                presented_redirect,
                state_param,
                &OAuthError::AccessDenied,
            );
        }
        Err(_) => {
            return authorize_error_redirect(
                presented_redirect,
                state_param,
                &OAuthError::ServerError,
            );
        }
    }

    // Step 4: issue the code.
    let issued = match codes::issue(
        app.id,
        user_id,
        presented_redirect,
        &scope.join(" "),
        q.nonce.as_deref(),
        challenge,
        method,
        claims.auth_time.unwrap_or(claims.iat),
        claims.session_version,
        Some(claims.session_exp.unwrap_or(claims.exp)),
        &mut conn,
    )
    .await
    {
        Ok(c) => c,
        Err(_) => {
            return authorize_error_redirect(
                presented_redirect,
                state_param,
                &OAuthError::ServerError,
            );
        }
    };

    info!(
        user_id = %user_id,
        client_id = %client_id,
        "oidc authorize success"
    );
    let _ = audit(AuditEventType::OidcAuthorizeSuccess)
        .user(user_id)
        .ctx(&audit_ctx)
        .details(json!({
            "client_id": client_id,
            "scope": scope.join(" "),
        }))
        .save(&mut conn)
        .await;

    let mut params: Vec<(&str, &str)> = vec![("code", &issued.plaintext)];
    if let Some(st) = state_param {
        params.push(("state", st));
    }
    redirect(StatusCode::FOUND, append_query(presented_redirect, &params))
}

fn login_redirect(uri: &Uri) -> Response {
    let path_and_query = uri
        .path_and_query()
        .map(|pq| pq.to_string())
        .unwrap_or_else(|| "/oauth/authorize".to_string());
    let target = format!(
        "/login?redirect_uri={}",
        urlencoding::encode(&path_and_query)
    );
    redirect(StatusCode::FOUND, target)
}

// ============================================================================
// Token endpoint
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct TokenForm {
    pub grant_type: Option<String>,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub code_verifier: Option<String>,
}

fn parse_basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let raw = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok())?;
    let (scheme, b64) = raw.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Basic") {
        return None;
    }
    let decoded = B64.decode(b64.trim()).ok()?;
    let s = std::str::from_utf8(&decoded).ok()?;
    let (id, secret) = s.split_once(':')?;
    // Per RFC 6749 §2.3.1 client_id and secret are URL-decoded when sent in Basic.
    let id = urlencoding::decode(&id.replace('+', " "))
        .ok()?
        .into_owned();
    let secret = urlencoding::decode(&secret.replace('+', " "))
        .ok()?
        .into_owned();
    Some((id, secret))
}

#[utoipa::path(
    post,
    path = "/oauth/token",
    request_body(content = TokenResponse, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, description = "Access token + id_token", body = TokenResponse),
        (status = 400, description = "invalid_request / invalid_grant / invalid_scope"),
        (status = 401, description = "invalid_client"),
        (status = 429, description = "Too many requests")
    ),
    tag = OIDC_TAG,
)]
pub async fn token(
    State(state): State<AppState>,
    audit_ctx: AuditContext,
    headers: HeaderMap,
    Form(form): Form<TokenForm>,
) -> Response {
    if let Err(retry_after) = state.oidc_token_rate_limiter.check(audit_ctx.ip).await {
        warn!(ip = %audit_ctx.ip, "oidc token rate limit exceeded");
        return RateLimitExceeded { retry_after }.into_response();
    }

    let mut conn = match state.db_pool.acquire().await {
        Ok(c) => c,
        Err(_) => return OAuthError::ServerError.into_response(),
    };

    // Reject malformed or conflicting authentication instead of falling back to a second
    // mechanism. OAuth clients must use only one client authentication method per request.
    let basic = parse_basic_auth(&headers);
    if headers.contains_key(AUTHORIZATION)
        && (basic.is_none() || headers.get_all(AUTHORIZATION).iter().count() != 1)
    {
        return OAuthError::InvalidClient.into_response();
    }
    if let Some((id, _)) = &basic
        && (form.client_secret.is_some()
            || form
                .client_id
                .as_deref()
                .is_some_and(|body_id| body_id != id))
    {
        return OAuthError::InvalidRequest("conflicting client authentication").into_response();
    }
    let client_id = basic
        .as_ref()
        .map(|(id, _)| id.clone())
        .or_else(|| form.client_id.clone());
    let presented_secret = basic
        .as_ref()
        .map(|(_, secret)| secret.clone())
        .or_else(|| form.client_secret.clone());

    let client_id = match client_id {
        Some(s) if !s.is_empty() => s,
        _ => return OAuthError::InvalidClient.into_response(),
    };

    if form.grant_type.as_deref() != Some("authorization_code") {
        return OAuthError::UnsupportedGrantType.into_response();
    }

    let app = match Application::get_by_oidc_client_id(&client_id, &mut conn).await {
        Ok(Some(a)) => a,
        Ok(None) => return OAuthError::InvalidClient.into_response(),
        Err(_) => return OAuthError::ServerError.into_response(),
    };
    if !app.enabled || app.app_type != AppType::Oidc {
        return OAuthError::UnauthorizedClient.into_response();
    }

    // Client authentication.
    if app.oidc_confidential {
        let Some(secret) = presented_secret.as_deref() else {
            return OAuthError::InvalidClient.into_response();
        };
        if !app.verify_client_secret(secret) {
            let _ = audit(AuditEventType::OidcTokenRejected)
                .ctx(&audit_ctx)
                .details(json!({ "client_id": client_id, "reason": "invalid_client_secret" }))
                .save(&mut conn)
                .await;
            return OAuthError::InvalidClient.into_response();
        }
    }
    // Public clients: no secret, PKCE alone authenticates the session.

    let code_str = match form.code.as_deref() {
        Some(s) if !s.is_empty() => s,
        _ => return OAuthError::InvalidRequest("missing code").into_response(),
    };
    let redirect_uri = match form.redirect_uri.as_deref() {
        Some(s) if !s.is_empty() => s,
        _ => return OAuthError::InvalidRequest("missing redirect_uri").into_response(),
    };
    let code_verifier = match form.code_verifier.as_deref() {
        Some(s) if !s.is_empty() => s,
        _ => return OAuthError::InvalidRequest("missing code_verifier").into_response(),
    };

    let consumed =
        match codes::consume(code_str, app.id, redirect_uri, code_verifier, &mut conn).await {
            Ok(Some(code)) => code,
            Ok(None) => {
                let _ = audit(AuditEventType::OidcTokenRejected)
                    .ctx(&audit_ctx)
                    .details(json!({ "client_id": client_id, "reason": "invalid_code" }))
                    .save(&mut conn)
                    .await;
                return OAuthError::InvalidGrant("code or authorization binding invalid")
                    .into_response();
            }
            Err(_) => return OAuthError::ServerError.into_response(),
        };
    if verify_user_session(
        consumed.user_id,
        consumed.auth_time,
        consumed.session_version,
        &mut conn,
    )
    .await
    .is_err()
        || !app.validate_redirect_uri(redirect_uri)
    {
        return OAuthError::InvalidGrant("authorization is no longer valid").into_response();
    }

    let user = match User::get(consumed.user_id, &mut conn).await {
        Ok(Some(u)) if u.active => u,
        _ => {
            let _ = audit(AuditEventType::OidcTokenRejected)
                .ctx(&audit_ctx)
                .details(json!({ "client_id": client_id, "reason": "user_inactive" }))
                .save(&mut conn)
                .await;
            return OAuthError::InvalidGrant("user no longer active").into_response();
        }
    };
    let roles = match user.get_roles(&mut conn).await {
        Ok(r) => r,
        Err(_) => return OAuthError::ServerError.into_response(),
    };
    match app.check_access_resolved(&roles, &mut conn).await {
        Ok(true) => {}
        Ok(false) => {
            return OAuthError::InvalidGrant("application access was revoked").into_response();
        }
        Err(_) => return OAuthError::ServerError.into_response(),
    }

    let scope = parse_scope(&consumed.scope);
    let token_response = match mint_token_pair(
        &state.origin,
        &app,
        &user,
        &roles,
        &scope,
        consumed.nonce,
        consumed.auth_time,
        &state.signing_key,
        &state.signing_kid,
        consumed.session_version,
        consumed.session_exp,
    ) {
        Ok(r) => r,
        Err(_) => return OAuthError::ServerError.into_response(),
    };

    let _ = audit(AuditEventType::OidcTokenIssued)
        .user(user.id)
        .ctx(&audit_ctx)
        .details(json!({ "client_id": client_id, "scope": scope.join(" ") }))
        .save(&mut conn)
        .await;

    // Cache-Control per RFC 6749 §5.1.
    let mut resp = axum::Json(token_response).into_response();
    resp.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        "no-store".parse().unwrap(),
    );
    resp.headers_mut()
        .insert(axum::http::header::PRAGMA, "no-cache".parse().unwrap());
    resp
}

// ============================================================================
// UserInfo endpoint
// ============================================================================

#[utoipa::path(
    get,
    path = "/oauth/userinfo",
    responses(
        (status = 200, description = "UserInfo claims (filtered by scope)"),
        (status = 401, description = "Missing or invalid bearer token")
    ),
    tag = OIDC_TAG,
)]
pub async fn userinfo(
    State(state): State<AppState>,
    audit_ctx: AuditContext,
    headers: HeaderMap,
) -> Response {
    let bearer = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_string);
    let Some(token) = bearer else {
        return unauthorized_with_bearer_challenge();
    };

    let claims = match verify_oidc_access_token(&token, &state.origin, &state.signing_key) {
        Ok(c) => c,
        Err(_) => return unauthorized_with_bearer_challenge(),
    };

    let user_id = match Uuid::parse_str(&claims.sub) {
        Ok(u) => u,
        Err(_) => return unauthorized_with_bearer_challenge(),
    };

    let mut conn = match state.db_pool.acquire().await {
        Ok(c) => c,
        Err(_) => return OAuthError::ServerError.into_response(),
    };

    if verify_user_session(user_id, claims.iat, claims.session_version, &mut conn)
        .await
        .is_err()
    {
        return unauthorized_with_bearer_challenge();
    }
    let app = match Application::get_by_oidc_client_id(&claims.aud, &mut conn).await {
        Ok(Some(app)) if app.enabled => app,
        Ok(_) => return unauthorized_with_bearer_challenge(),
        Err(_) => return OAuthError::ServerError.into_response(),
    };

    let user = match User::get(user_id, &mut conn).await {
        Ok(Some(u)) if u.active => u,
        _ => return unauthorized_with_bearer_challenge(),
    };
    let user_roles = match user.get_roles(&mut conn).await {
        Ok(r) => r,
        Err(_) => return OAuthError::ServerError.into_response(),
    };
    match app.check_access_resolved(&user_roles, &mut conn).await {
        Ok(true) => {}
        Ok(false) => return unauthorized_with_bearer_challenge(),
        Err(_) => return OAuthError::ServerError.into_response(),
    }

    let scope = parse_scope(&claims.scope);
    let mut body = json!({ "sub": user.id.to_string() });
    if scope_contains(&scope, token::SCOPE_PROFILE) {
        body["name"] = json!(user.name);
        body["preferred_username"] = json!(user.username);
        body["updated_at"] = json!(user.updated_at);
    }
    if scope_contains(&scope, token::SCOPE_EMAIL)
        && let Some(email) = &user.email
    {
        body["email"] = json!(email);
    }
    if scope_contains(&scope, token::SCOPE_ROLES) {
        body["roles"] = json!(user_roles);
    }

    let _ = audit(AuditEventType::OidcUserinfoAccessed)
        .user(user.id)
        .ctx(&audit_ctx)
        .details(json!({ "client_id": claims.aud, "scope": claims.scope }))
        .save(&mut conn)
        .await;

    ([(header::CACHE_CONTROL, "no-store")], axum::Json(body)).into_response()
}

fn unauthorized_with_bearer_challenge() -> Response {
    let mut resp = (StatusCode::UNAUTHORIZED, "").into_response();
    resp.headers_mut().insert(
        WWW_AUTHENTICATE,
        "Bearer realm=\"oidc\", error=\"invalid_token\""
            .parse()
            .unwrap(),
    );
    resp
}

// ============================================================================
// RP-initiated logout
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct EndSessionQuery {
    pub id_token_hint: Option<String>,
    pub client_id: Option<String>,
    pub post_logout_redirect_uri: Option<String>,
    pub state: Option<String>,
}

#[utoipa::path(
    get,
    path = "/oauth/end_session",
    responses(
        (status = 302, description = "Redirect to post_logout_redirect_uri or a default page"),
        (status = 200, description = "Signed out (default landing page)")
    ),
    tag = OIDC_TAG,
)]
pub async fn end_session(
    State(state): State<AppState>,
    audit_ctx: AuditContext,
    headers: HeaderMap,
    Query(q): Query<EndSessionQuery>,
) -> Response {
    end_session_impl(state, audit_ctx, headers, q, false, false).await
}

#[utoipa::path(
    post,
    path = "/oauth/end_session",
    responses(
        (status = 302, description = "Redirect after confirmed logout"),
        (status = 200, description = "Signed out or confirmation required")
    ),
    tag = OIDC_TAG,
)]
pub async fn end_session_post(
    State(state): State<AppState>,
    audit_ctx: AuditContext,
    headers: HeaderMap,
    Form(q): Form<EndSessionQuery>,
) -> Response {
    // The OP's own confirmation form posts from the configured origin. A cross-site RP
    // POST can still log out using a valid matching ID token hint below.
    let expected_origin = url::Url::parse(&state.origin)
        .map(|url| url.origin().ascii_serialization())
        .ok();
    let confirmed = headers
        .get(header::ORIGIN)
        .and_then(|h| h.to_str().ok())
        .zip(expected_origin.as_deref())
        .is_some_and(|(actual, expected)| actual == expected);
    end_session_impl(state, audit_ctx, headers, q, confirmed, !confirmed).await
}

async fn end_session_impl(
    state: AppState,
    audit_ctx: AuditContext,
    headers: HeaderMap,
    q: EndSessionQuery,
    confirmed: bool,
    require_matching_session: bool,
) -> Response {
    let mut renewed = None;
    let mut response = end_session_response(
        state,
        audit_ctx,
        headers,
        q,
        confirmed,
        require_matching_session,
        &mut renewed,
    )
    .await;
    if require_matching_session && response.status().is_client_error() {
        return (
            StatusCode::FORBIDDEN,
            "A matching browser session and ID token hint are required",
        )
            .into_response();
    }
    if !response.headers().contains_key(SET_COOKIE)
        && let Some(pair) = renewed
    {
        append_session_cookies(&mut response, &pair);
    }
    response
}

async fn end_session_response(
    state: AppState,
    audit_ctx: AuditContext,
    headers: HeaderMap,
    q: EndSessionQuery,
    confirmed: bool,
    require_matching_session: bool,
    renewed: &mut Option<TokenPair>,
) -> Response {
    let mut conn = match state.db_pool.acquire().await {
        Ok(c) => c,
        Err(_) => return OAuthError::ServerError.into_response(),
    };

    // An ID token hint identifies a client and user; it is not authority to revoke
    // arbitrary users' sessions. Decode the ID token shape to reject access tokens.
    let hint = if let Some(hint) = q.id_token_hint.as_deref() {
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
        validation.set_required_spec_claims(&["sub", "iss", "aud", "iat", "exp"]);
        validation.set_issuer(&[&state.origin]);
        validation.validate_exp = false;
        validation.validate_aud = false;
        let decoding_key =
            jsonwebtoken::DecodingKey::from_ed_der(&state.signing_key.verifying_key().to_bytes());
        match jsonwebtoken::decode::<token::IdTokenClaims>(hint, &decoding_key, &validation) {
            Ok(data) => Some(data.claims),
            Err(_) => return OAuthError::InvalidRequest("invalid id_token_hint").into_response(),
        }
    } else {
        None
    };
    if let (Some(client_id), Some(hint)) = (q.client_id.as_deref(), hint.as_ref())
        && client_id != hint.aud
    {
        return OAuthError::InvalidRequest("client_id does not match id_token_hint")
            .into_response();
    }
    let client_id = q
        .client_id
        .as_deref()
        .or_else(|| hint.as_ref().map(|hint| hint.aud.as_str()));
    let app = match client_id {
        Some(id) if !id.is_empty() => {
            match Application::get_by_oidc_client_id(id, &mut conn).await {
                Ok(Some(app)) if app.enabled => Some(app),
                Ok(_) => return OAuthError::InvalidClient.into_response(),
                Err(_) => return OAuthError::ServerError.into_response(),
            }
        }
        _ => None,
    };

    let session = if require_matching_session {
        // Cross-origin POSTs may omit SameSite cookies. Never let such a request clear
        // the browser's real cookies, or rotate a refresh token before its hint is bound
        // to the current browser. A refresh-only browser can use the GET confirmation.
        if hint.is_none() {
            return StatusCode::FORBIDDEN.into_response();
        }
        let Some(access) = extract_session_cookie(&headers) else {
            return StatusCode::FORBIDDEN.into_response();
        };
        match verify_access_token(&access, &state.signing_key, &mut conn).await {
            Ok(session) => Some(session),
            Err(crate::errors::AppError::AuthenticationRequired) => {
                return StatusCode::FORBIDDEN.into_response();
            }
            Err(_) => return OAuthError::ServerError.into_response(),
        }
    } else {
        match resolve_browser_session(&state, &headers, &mut conn, renewed).await {
            Ok(session) => session,
            Err(_) => return OAuthError::ServerError.into_response(),
        }
    };

    if let Some(session) = session {
        let uid = match Uuid::parse_str(&session.sub) {
            Ok(uid) => uid,
            Err(_) => return OAuthError::ServerError.into_response(),
        };
        let matching_hint = match hint.as_ref() {
            Some(hint)
                if hint.sub == session.sub
                    && hint.auth_time == session.auth_time.unwrap_or(session.iat) =>
            {
                verify_user_session(uid, hint.iat, hint.session_version, &mut conn)
                    .await
                    .is_ok()
            }
            _ => false,
        };
        if require_matching_session && !matching_hint {
            return StatusCode::FORBIDDEN.into_response();
        }
        if !confirmed && !matching_hint {
            return (
                [
                    (header::CONTENT_TYPE, "text/html; charset=utf-8"),
                    (header::CACHE_CONTROL, "no-store"),
                    (header::REFERRER_POLICY, "no-referrer"),
                    (
                        header::CONTENT_SECURITY_POLICY,
                        "frame-ancestors 'none'; form-action 'self'",
                    ),
                ],
                build_logout_confirmation_html(&q, client_id),
            )
                .into_response();
        }
        if revoke_all_user_tokens(uid, &mut conn).await.is_err() {
            return OAuthError::ServerError.into_response();
        }
        let _ = audit(AuditEventType::OidcLogout)
            .user(uid)
            .ctx(&audit_ctx)
            .details(json!({
                "client_id": client_id.unwrap_or_default(),
            }))
            .save(&mut conn)
            .await;
    }

    let clear = clear_auth_cookies();
    let mut resp_headers = HeaderMap::new();
    resp_headers.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    resp_headers.insert(header::REFERRER_POLICY, "no-referrer".parse().unwrap());
    resp_headers.insert(SET_COOKIE, clear[0].parse().unwrap());
    resp_headers.append(SET_COOKIE, clear[1].parse().unwrap());

    // If the RP provided an allowed post_logout_redirect_uri, bounce there.
    if let Some(uri) = q.post_logout_redirect_uri.as_deref()
        && let Some(app) = app.as_ref()
        && app.validate_post_logout_redirect_uri(uri)
    {
        let mut params: Vec<(&str, &str)> = Vec::new();
        if let Some(s) = q.state.as_deref() {
            params.push(("state", s));
        }
        let location = append_query(uri, &params);
        let Ok(location) = location.parse() else {
            return OAuthError::InvalidRequest("invalid post_logout_redirect_uri").into_response();
        };
        resp_headers.insert(LOCATION, location);
        return (StatusCode::FOUND, resp_headers).into_response();
    }

    let html = build_signed_out_html(&state.origin, app.as_ref().map(|a| a.name.as_str()));
    resp_headers.insert(
        header::CONTENT_TYPE,
        "text/html; charset=utf-8".parse().unwrap(),
    );
    resp_headers.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    (StatusCode::OK, resp_headers, html).into_response()
}

fn build_logout_confirmation_html(q: &EndSessionQuery, client_id: Option<&str>) -> String {
    let mut inputs = String::new();
    // Deliberately omit a missing/mismatched hint. The user confirms their own current
    // browser session; a hint for another user must never select the revocation target.
    for (name, value) in [
        ("client_id", client_id),
        (
            "post_logout_redirect_uri",
            q.post_logout_redirect_uri.as_deref(),
        ),
        ("state", q.state.as_deref()),
    ] {
        if let Some(value) = value {
            inputs.push_str(&format!(
                r#"<input type="hidden" name="{name}" value="{}">"#,
                html_escape(value)
            ));
        }
    }
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Confirm sign out</title></head><body><main><h1>Sign out of Authere?</h1><p>This will sign you out of Authere on all devices.</p><form method="post" action="/oauth/end_session">{inputs}<button type="submit">Sign out</button></form><a href="/">Cancel</a></main></body></html>"#
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Render the styled HTML page shown after RP-initiated logout when no
/// `post_logout_redirect_uri` redirect is performed. Matches the login screen's
/// dark dot-grid look and surfaces the application name (when known) so the user
/// knows which session was ended.
fn build_signed_out_html(origin: &str, app_name: Option<&str>) -> String {
    let sign_in_url = html_escape(&format!("{origin}/login"));

    let app_block = match app_name {
        Some(name) if !name.is_empty() => format!(
            r#"<div class="details"><div class="row"><span class="label">Application</span><span class="value">{}</span></div></div>"#,
            html_escape(name)
        ),
        _ => String::new(),
    };

    let lede = match app_name {
        Some(name) if !name.is_empty() => format!(
            r#"<p class="subtle">Your session for {} has ended. You can sign back in to continue.</p>"#,
            html_escape(name)
        ),
        _ => r#"<p class="subtle">Your session has ended. You can sign back in to continue.</p>"#
            .to_string(),
    };

    format!(
        r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Signed out</title>
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
        <h1>You're signed out</h1>
        {lede}
      </div>

      {app_block}

      <div class="actions">
        <a class="btn btn-primary" href="{sign_in_url}">Sign in again</a>
      </div>
    </div>
  </div>
</body>
</html>
"##
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_query_with_no_existing_params() {
        let r = append_query(
            "https://app.example/cb",
            &[("code", "abc"), ("state", "xyz")],
        );
        assert_eq!(r, "https://app.example/cb?code=abc&state=xyz");
    }

    #[test]
    fn append_query_preserves_existing_params() {
        let r = append_query("https://app.example/cb?foo=bar", &[("code", "abc")]);
        assert_eq!(r, "https://app.example/cb?foo=bar&code=abc");
    }

    #[test]
    fn append_query_url_encodes_values() {
        let r = append_query("https://app.example/cb", &[("state", "a b/c?d")]);
        assert!(r.ends_with("state=a%20b%2Fc%3Fd"));
    }

    #[test]
    fn parse_basic_auth_extracts_credentials() {
        let mut h = HeaderMap::new();
        let b64 = B64.encode("myclient:s3cret");
        h.insert(AUTHORIZATION, format!("Basic {b64}").parse().unwrap());
        let (id, secret) = parse_basic_auth(&h).unwrap();
        assert_eq!(id, "myclient");
        assert_eq!(secret, "s3cret");
    }

    #[test]
    fn parse_basic_auth_returns_none_when_missing() {
        let h = HeaderMap::new();
        assert!(parse_basic_auth(&h).is_none());
    }

    #[test]
    fn parse_basic_auth_returns_none_for_non_basic_scheme() {
        let mut h = HeaderMap::new();
        h.insert(AUTHORIZATION, "Bearer xyz".parse().unwrap());
        assert!(parse_basic_auth(&h).is_none());
    }

    #[test]
    fn parse_basic_auth_rejects_invalid_base64() {
        let mut h = HeaderMap::new();
        h.insert(AUTHORIZATION, "Basic !!!not-base64!!!".parse().unwrap());
        assert!(parse_basic_auth(&h).is_none());
    }

    #[test]
    fn parse_basic_auth_urldecodes_values() {
        let mut h = HeaderMap::new();
        // RFC 6749 §2.3.1 mandates URL-encoding for characters outside [ALPHA, DIGIT, "-._~"]
        // before base64. "secret!" → "secret%21" → base64.
        let b64 = B64.encode("client%20id:pa%21ss");
        h.insert(AUTHORIZATION, format!("Basic {b64}").parse().unwrap());
        let (id, secret) = parse_basic_auth(&h).unwrap();
        assert_eq!(id, "client id");
        assert_eq!(secret, "pa!ss");
    }

    #[test]
    fn oauth_error_token_status_invalid_client_is_401() {
        assert_eq!(
            OAuthError::InvalidClient.token_endpoint_status(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[test]
    fn oauth_error_token_status_other_is_400() {
        assert_eq!(
            OAuthError::UnsupportedGrantType.token_endpoint_status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            OAuthError::InvalidGrant("x").token_endpoint_status(),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn oauth_error_codes_are_standard() {
        assert_eq!(OAuthError::InvalidRequest("x").code(), "invalid_request");
        assert_eq!(OAuthError::InvalidClient.code(), "invalid_client");
        assert_eq!(OAuthError::InvalidGrant("x").code(), "invalid_grant");
        assert_eq!(OAuthError::UnauthorizedClient.code(), "unauthorized_client");
        assert_eq!(
            OAuthError::UnsupportedResponseType.code(),
            "unsupported_response_type"
        );
        assert_eq!(
            OAuthError::UnsupportedGrantType.code(),
            "unsupported_grant_type"
        );
        assert_eq!(OAuthError::InvalidScope.code(), "invalid_scope");
        assert_eq!(OAuthError::AccessDenied.code(), "access_denied");
        assert_eq!(OAuthError::ServerError.code(), "server_error");
    }

    #[test]
    fn discovery_document_has_required_fields() {
        let d = build_discovery("https://authere.example");
        assert_eq!(d.issuer, "https://authere.example");
        assert_eq!(
            d.authorization_endpoint,
            "https://authere.example/oauth/authorize"
        );
        assert_eq!(d.token_endpoint, "https://authere.example/oauth/token");
        assert_eq!(
            d.userinfo_endpoint,
            "https://authere.example/oauth/userinfo"
        );
        assert_eq!(
            d.end_session_endpoint,
            "https://authere.example/oauth/end_session"
        );
        assert_eq!(d.jwks_uri, "https://authere.example/.well-known/jwks.json");
        assert!(d.response_types_supported.contains(&"code".to_string()));
        assert!(d.scopes_supported.contains(&"openid".to_string()));
        assert!(
            d.id_token_signing_alg_values_supported
                .contains(&"EdDSA".to_string())
        );
        assert!(
            d.code_challenge_methods_supported
                .contains(&"S256".to_string())
        );
    }

    #[test]
    fn extract_session_cookie_picks_correct_cookie() {
        let mut h = HeaderMap::new();
        h.insert(
            "cookie",
            "foo=1; __Host-authere_token=the-token; bar=2"
                .parse()
                .unwrap(),
        );
        assert_eq!(extract_session_cookie(&h).as_deref(), Some("the-token"));
    }

    #[test]
    fn extract_session_cookie_returns_none_without_cookie() {
        let h = HeaderMap::new();
        assert!(extract_session_cookie(&h).is_none());
    }

    #[test]
    fn html_escape_replaces_special_chars() {
        assert_eq!(
            html_escape(r#"<script>alert("x&y's")</script>"#),
            "&lt;script&gt;alert(&quot;x&amp;y&#39;s&quot;)&lt;/script&gt;",
        );
    }

    #[test]
    fn signed_out_html_contains_brand_and_sign_in_link() {
        let body = build_signed_out_html("https://authere.example", Some("Production Dashboard"));
        assert!(body.contains("<title>Signed out</title>"));
        assert!(body.contains("You're signed out"));
        assert!(body.contains("Production Dashboard"));
        // Sign-in CTA points back at the host's /login.
        assert!(body.contains(r#"href="https://authere.example/login""#));
        // Same brand mark as the login screen.
        assert!(body.contains(">authere</span>"));
    }

    #[test]
    fn signed_out_html_omits_app_block_when_unknown() {
        let body = build_signed_out_html("https://authere.example", None);
        assert!(!body.contains(r#"class="details""#));
        assert!(body.contains("Your session has ended."));
    }

    #[test]
    fn signed_out_html_escapes_app_name() {
        let body = build_signed_out_html("https://authere.example", Some("<evil> & co"));
        assert!(body.contains("&lt;evil&gt; &amp; co"));
        assert!(!body.contains("<evil>"));
    }

    #[test]
    fn signed_out_html_treats_empty_app_name_as_missing() {
        let body = build_signed_out_html("https://authere.example", Some(""));
        assert!(!body.contains(r#"class="details""#));
    }
}

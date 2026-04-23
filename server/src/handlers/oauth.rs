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
use axum::http::header::{AUTHORIZATION, LOCATION, SET_COOKIE, WWW_AUTHENTICATE};
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
use crate::handlers::{AUTH_COOKIE_NAME, REFRESH_COOKIE_NAME, clear_auth_cookies};
use crate::oidc::codes;
use crate::oidc::jwks::build_jwks;
use crate::oidc::token::{
    self, SCOPE_OPENID, TokenResponse, mint_token_pair, parse_scope, scope_contains,
    verify_oidc_access_token,
};
use crate::rate_limit::RateLimitExceeded;
use crate::user::User;
use crate::user::auth::token::{revoke_all_user_tokens, verify_access_token};

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
            OAuthError::ServerError => "server_error",
        }
    }

    fn description(&self) -> Option<&'static str> {
        match self {
            OAuthError::InvalidRequest(m)
            | OAuthError::InvalidGrant(m) => Some(m),
            _ => None,
        }
    }

    fn token_endpoint_status(&self) -> StatusCode {
        match self {
            OAuthError::InvalidClient => StatusCode::UNAUTHORIZED,
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
        if matches!(self, OAuthError::InvalidClient) {
            resp.headers_mut()
                .insert(WWW_AUTHENTICATE, "Basic realm=\"oidc\"".parse().unwrap());
        }
        resp
    }
}

/// Extract the Authere session cookie (authere_token) from the request.
fn extract_session_cookie(headers: &HeaderMap) -> Option<String> {
    headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies
                .split(';')
                .map(|s| s.trim())
                .find(|s| s.starts_with(&format!("{AUTH_COOKIE_NAME}=")))
                .and_then(|s| s.strip_prefix(&format!("{AUTH_COOKIE_NAME}=")))
                .map(|s| s.to_string())
        })
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
        scopes_supported: vec!["openid".into(), "profile".into(), "email".into(), "roles".into()],
        token_endpoint_auth_methods_supported: vec![
            "client_secret_basic".into(),
            "client_secret_post".into(),
            "none".into(),
        ],
        grant_types_supported: vec!["authorization_code".into()],
        code_challenge_methods_supported: vec!["S256".into()],
        claims_supported: vec![
            "sub".into(), "iss".into(), "aud".into(), "exp".into(), "iat".into(),
            "auth_time".into(), "nonce".into(), "name".into(), "preferred_username".into(),
            "updated_at".into(), "email".into(), "roles".into(),
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
pub async fn discovery(
    State(state): State<AppState>,
) -> axum::Json<DiscoveryDocument> {
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
    (status, [(LOCATION, location)]).into_response()
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

    let scope = parse_scope(q.scope.as_deref().unwrap_or(""));
    if !scope_contains(&scope, SCOPE_OPENID) {
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
    let method = q.code_challenge_method.as_deref().unwrap_or("S256");
    if method != "S256" {
        return authorize_error_redirect(
            presented_redirect,
            state_param,
            &OAuthError::InvalidRequest("code_challenge_method must be S256"),
        );
    }

    // Step 2: check the user's Authere session. Missing/expired -> bounce through /login.
    let session_cookie = extract_session_cookie(&headers);
    let claims = match session_cookie.as_deref() {
        Some(t) => match verify_access_token(t, &state.signing_key, &mut conn).await {
            Ok(c) => c,
            Err(_) => return login_redirect(&uri),
        },
        None => return login_redirect(&uri),
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

    // Step 3: role gating.
    match app.check_access_resolved(&claims.roles, &mut conn).await {
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
        claims.iat,
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
    let target = format!("/login?redirect_uri={}", urlencoding::encode(&path_and_query));
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
    let b64 = raw.strip_prefix("Basic ")?;
    let decoded = B64.decode(b64.trim()).ok()?;
    let s = std::str::from_utf8(&decoded).ok()?;
    let (id, secret) = s.split_once(':')?;
    // Per RFC 6749 §2.3.1 client_id and secret are URL-decoded when sent in Basic.
    let id = urlencoding::decode(id).ok()?.into_owned();
    let secret = urlencoding::decode(secret).ok()?.into_owned();
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

    // Resolve client credentials: Basic header takes precedence; otherwise use form body.
    let basic = parse_basic_auth(&headers);
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

    let Some(consumed) = codes::consume(code_str, &mut conn).await.unwrap_or(None) else {
        let _ = audit(AuditEventType::OidcTokenRejected)
            .ctx(&audit_ctx)
            .details(json!({ "client_id": client_id, "reason": "invalid_code" }))
            .save(&mut conn)
            .await;
        return OAuthError::InvalidGrant("code invalid, consumed, or expired").into_response();
    };

    if consumed.application_id != app.id {
        let _ = audit(AuditEventType::OidcTokenRejected)
            .ctx(&audit_ctx)
            .details(json!({ "client_id": client_id, "reason": "client_mismatch" }))
            .save(&mut conn)
            .await;
        return OAuthError::InvalidGrant("code was issued to a different client").into_response();
    }

    if consumed.redirect_uri != redirect_uri {
        let _ = audit(AuditEventType::OidcTokenRejected)
            .user(consumed.user_id)
            .ctx(&audit_ctx)
            .details(json!({ "client_id": client_id, "reason": "redirect_uri_mismatch" }))
            .save(&mut conn)
            .await;
        return OAuthError::InvalidGrant("redirect_uri mismatch").into_response();
    }

    if consumed.code_challenge_method != "S256"
        || !codes::verify_pkce_s256(code_verifier, &consumed.code_challenge)
    {
        let _ = audit(AuditEventType::OidcTokenRejected)
            .user(consumed.user_id)
            .ctx(&audit_ctx)
            .details(json!({ "client_id": client_id, "reason": "pkce_failed" }))
            .save(&mut conn)
            .await;
        return OAuthError::InvalidGrant("PKCE verification failed").into_response();
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

    let user = match User::get(user_id, &mut conn).await {
        Ok(Some(u)) if u.active => u,
        _ => return unauthorized_with_bearer_challenge(),
    };
    let user_roles = match user.get_roles(&mut conn).await {
        Ok(r) => r,
        Err(_) => return OAuthError::ServerError.into_response(),
    };

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

    axum::Json(body).into_response()
}

fn unauthorized_with_bearer_challenge() -> Response {
    let mut resp = (StatusCode::UNAUTHORIZED, "").into_response();
    resp.headers_mut().insert(
        WWW_AUTHENTICATE,
        "Bearer realm=\"oidc\", error=\"invalid_token\"".parse().unwrap(),
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
    let mut conn = match state.db_pool.acquire().await {
        Ok(c) => c,
        Err(_) => return OAuthError::ServerError.into_response(),
    };

    // Resolve the client (optional but preferred when the RP provides id_token_hint).
    let app = match q.client_id.as_deref() {
        Some(id) if !id.is_empty() => {
            Application::get_by_oidc_client_id(id, &mut conn).await.unwrap_or(None)
        }
        _ => None,
    };

    // Best-effort user resolution from id_token_hint or current session cookie.
    let mut sub_user_id: Option<Uuid> = None;
    if let Some(hint) = q.id_token_hint.as_deref() {
        // We intentionally tolerate expired hints here per OIDC RP-initiated logout §5 —
        // the point is to sign the user out, and their id_token may well be stale.
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
        validation.set_required_spec_claims(&["sub", "iss", "aud"]);
        validation.set_issuer(&[&state.origin]);
        validation.validate_exp = false;
        validation.validate_aud = false;
        let decoding_key = jsonwebtoken::DecodingKey::from_ed_der(
            &state.signing_key.verifying_key().to_bytes(),
        );
        if let Ok(data) = jsonwebtoken::decode::<serde_json::Value>(hint, &decoding_key, &validation)
            && let Some(sub) = data.claims.get("sub").and_then(|v| v.as_str())
            && let Ok(u) = Uuid::parse_str(sub)
        {
            sub_user_id = Some(u);
        }
    }
    if sub_user_id.is_none()
        && let Some(tok) = extract_session_cookie(&headers)
        && let Ok(claims) = verify_access_token(&tok, &state.signing_key, &mut conn).await
        && let Ok(u) = Uuid::parse_str(&claims.sub)
    {
        sub_user_id = Some(u);
    }

    if let Some(uid) = sub_user_id {
        let _ = revoke_all_user_tokens(uid, &mut conn).await;
        let _ = audit(AuditEventType::OidcLogout)
            .user(uid)
            .ctx(&audit_ctx)
            .details(json!({
                "client_id": q.client_id.clone().unwrap_or_default(),
            }))
            .save(&mut conn)
            .await;
    }

    let clear = clear_auth_cookies();
    let mut resp_headers = HeaderMap::new();
    // Also clear the OIDC session-free cookie path we use on /login (kept consistent with
    // browser_logout).
    resp_headers.insert(SET_COOKIE, clear[0].parse().unwrap());
    resp_headers.append(SET_COOKIE, clear[1].parse().unwrap());
    // Redundantly scope clears to /oauth to handle cookies written under that path.
    resp_headers.append(
        SET_COOKIE,
        format!("{AUTH_COOKIE_NAME}=; HttpOnly; Secure; SameSite=Lax; Path=/oauth; Max-Age=0")
            .parse()
            .unwrap(),
    );
    resp_headers.append(
        SET_COOKIE,
        format!("{REFRESH_COOKIE_NAME}=; HttpOnly; Secure; SameSite=Strict; Path=/oauth; Max-Age=0")
            .parse()
            .unwrap(),
    );

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
        resp_headers.insert(LOCATION, location.parse().unwrap());
        return (StatusCode::FOUND, resp_headers).into_response();
    }

    (
        StatusCode::OK,
        resp_headers,
        axum::Json(json!({ "signed_out": true })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_query_with_no_existing_params() {
        let r = append_query("https://app.example/cb", &[("code", "abc"), ("state", "xyz")]);
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
        assert_eq!(d.authorization_endpoint, "https://authere.example/oauth/authorize");
        assert_eq!(d.token_endpoint, "https://authere.example/oauth/token");
        assert_eq!(d.userinfo_endpoint, "https://authere.example/oauth/userinfo");
        assert_eq!(d.end_session_endpoint, "https://authere.example/oauth/end_session");
        assert_eq!(d.jwks_uri, "https://authere.example/.well-known/jwks.json");
        assert!(d.response_types_supported.contains(&"code".to_string()));
        assert!(d.scopes_supported.contains(&"openid".to_string()));
        assert!(d.id_token_signing_alg_values_supported.contains(&"EdDSA".to_string()));
        assert!(d.code_challenge_methods_supported.contains(&"S256".to_string()));
    }

    #[test]
    fn extract_session_cookie_picks_correct_cookie() {
        let mut h = HeaderMap::new();
        h.insert(
            "cookie",
            "foo=1; authere_token=the-token; bar=2".parse().unwrap(),
        );
        assert_eq!(extract_session_cookie(&h).as_deref(), Some("the-token"));
    }

    #[test]
    fn extract_session_cookie_returns_none_without_cookie() {
        let h = HeaderMap::new();
        assert!(extract_session_cookie(&h).is_none());
    }
}


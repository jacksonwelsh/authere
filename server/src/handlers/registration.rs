use axum::extract::{self, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use utoipa::ToSchema;

use crate::AppState;
use crate::audit::{audit, AuditContext, AuditEventType};
use crate::db::DbEntity;
use crate::errors::AppError;
use crate::handlers::{RegisterError, build_auth_cookie, build_refresh_cookie};
use crate::handlers::auth::BrowserLoginResponse;
use crate::invitation::Invitation;
use crate::provisioning::{self, event::UserLifecycleEvent};
use crate::rate_limit::RateLimitExceeded;
use crate::role::{Role, UserRole, ROLE_USER};
use crate::settings::open_registration_enabled;
use crate::user::auth::Authenticator;
use crate::user::auth::token::{REFRESH_TOKEN_LIFETIME, generate_token_pair};
use crate::user::{CreateUserInput, User};

const AUTH_TAG: &str = "auth";

#[derive(Debug, Deserialize, ToSchema)]
pub struct RegisterInput {
    pub username: String,
    pub name: String,
    pub email: Option<String>,
    pub password: String,
    pub confirm_password: String,
    pub invite_code: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ValidateInviteQuery {
    pub code: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ValidateInviteResponse {
    pub valid: bool,
}

#[utoipa::path(
    post,
    path = "/api/register",
    request_body(content = RegisterInput),
    responses(
        (status = 200, description = "Registration successful, cookies set"),
        (status = 400, description = "Invalid input, registration closed, or invalid invite"),
        (status = 409, description = "Username already taken"),
        (status = 429, description = "Too many registration attempts"),
        (status = 500, description = "Internal server error")
    ),
    tag = AUTH_TAG,
)]
pub async fn register(
    State(state): State<AppState>,
    audit_ctx: AuditContext,
    extract::Json(input): extract::Json<RegisterInput>,
) -> Result<Response, RegisterError> {
    if let Err(retry_after) = state.register_rate_limiter.check(audit_ctx.ip).await {
        warn!(ip = %audit_ctx.ip, "registration rate limit exceeded");
        return Err(RegisterError::RateLimit(RateLimitExceeded { retry_after }));
    }

    if input.password != input.confirm_password {
        return Err(AppError::InputError(vec!["Passwords do not match".to_string()]).into());
    }

    let create_input = CreateUserInput {
        username: input.username.clone(),
        name: input.name.clone(),
        email: input.email.clone(),
        password: input.password.clone(),
    };
    User::validate_create_input(&create_input)?;

    let mut conn = state.db_pool.acquire().await?;
    let open = open_registration_enabled(&mut conn).await?;

    if !open {
        let code = input.invite_code.as_deref().ok_or_else(|| {
            AppError::InputError(vec!["Registration is by invitation only".to_string()])
        })?;

        let invite = Invitation::get(code, &mut conn)
            .await?
            .ok_or_else(|| AppError::InputError(vec!["Invitation is invalid or expired".to_string()]))?;

        if !invite.is_valid() {
            return Err(AppError::InputError(vec!["Invitation is invalid or expired".to_string()]).into());
        }
    }

    let user = User::new(input.username, input.name, input.email);
    let authenticator = Authenticator::new_password(input.password, user.id).map_err(|e| {
        AppError::InternalError(format!("Failed to create authenticator ({e})"))
    })?;

    let mut tx = state.db_pool.begin().await?;

    let consumed_invite = if !open {
        let code = input.invite_code.as_deref().unwrap();
        let consumed = Invitation::consume(code, &mut tx).await?.ok_or_else(|| {
            AppError::InputError(vec!["Invitation is invalid or expired".to_string()])
        })?;
        Some(consumed)
    } else {
        None
    };

    user.save(&mut tx).await?;
    authenticator.save(&mut tx).await?;

    if let Some(user_role) = Role::get_by_name(ROLE_USER, &mut tx).await? {
        let _ = UserRole::assign(user.id, user_role.id, &mut tx).await;
    }

    provisioning::enqueue(&user, UserLifecycleEvent::Created, &state.origin, &mut tx).await?;

    tx.commit().await?;
    state.provisioning_notifier.notify_one();

    info!(user_id = %user.id, username = %user.username, invite = consumed_invite.is_some(), "user registered");

    let invite_id = consumed_invite.as_ref().map(|i| i.id.as_str());
    let register_details = match invite_id {
        Some(id) => serde_json::json!({ "invite_used": true, "invite_id": id }),
        None => serde_json::json!({ "invite_used": false }),
    };
    let _ = audit(AuditEventType::UserRegistered)
        .user(user.id)
        .ctx(&audit_ctx)
        .details(register_details)
        .save(&mut conn)
        .await;
    if let Some(invite) = &consumed_invite {
        let _ = audit(AuditEventType::InvitationConsumed)
            .user(user.id)
            .ctx(&audit_ctx)
            .details(serde_json::json!({ "invite_id": invite.id }))
            .save(&mut conn)
            .await;
    }

    let token_pair = generate_token_pair(user.id, vec![ROLE_USER.to_string()], &state.signing_key, &mut conn).await?;

    let access_cookie = build_auth_cookie(&token_pair.access_token, token_pair.expires_in);
    let refresh_cookie = build_refresh_cookie(
        &token_pair.refresh_token,
        REFRESH_TOKEN_LIFETIME,
    );

    let mut headers = axum::http::header::HeaderMap::new();
    headers.insert(
        axum::http::header::SET_COOKIE,
        access_cookie.parse().unwrap(),
    );
    headers.append(
        axum::http::header::SET_COOKIE,
        refresh_cookie.parse().unwrap(),
    );

    Ok((
        StatusCode::OK,
        headers,
        axum::Json(BrowserLoginResponse {
            success: true,
            redirect_uri: Some("/account".to_string()),
        }),
    )
        .into_response())
}

#[utoipa::path(
    get,
    path = "/api/register/validate-invite",
    params(
        ("code" = String, Query, description = "Invitation code to validate")
    ),
    responses(
        (status = 200, description = "Validation result", body = ValidateInviteResponse),
    ),
    tag = AUTH_TAG,
)]
pub async fn validate_invite(
    State(state): State<AppState>,
    Query(query): Query<ValidateInviteQuery>,
) -> Result<axum::Json<ValidateInviteResponse>, AppError> {
    let mut conn = state.db_pool.acquire().await?;
    let valid = match Invitation::get(&query.code, &mut conn).await? {
        Some(invite) => invite.is_valid(),
        None => false,
    };
    Ok(axum::Json(ValidateInviteResponse { valid }))
}

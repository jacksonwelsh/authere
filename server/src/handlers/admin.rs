use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::IntoResponse;
use rand::Rng;
use serde::{Deserialize, Serialize};
use tracing::info;
use uuid::Uuid;

use crate::AppState;
use crate::audit::{audit, AuditContext, AuditEventType, AuditLogQuery, AuditLogRecord};
use crate::auth_middleware::AdminUser;
use crate::errors::AppError;
use crate::invitation::{CreateInvitationInput, Invitation, InvitationWithStatus};
use crate::settings::{
    KEY_LDAP_BASE_DN, KEY_LDAP_BIND_ADDRESS, KEY_LDAP_ENABLED, KEY_LDAP_PASSWORD_MODE,
    KEY_LDAP_SERVICE_PASSWORD_HASH, KEY_OPEN_REGISTRATION, KEY_SESSION_EXPIRY_SECONDS,
    LdapSettingsInput, SettingsResponse, UpdateSettingsInput, load_ldap_config,
    open_registration_enabled, session_expiry_seconds, set_setting, to_ldap_settings,
    validate_base_dn, validate_bind_address, validate_session_expiry_seconds,
};

const ADMIN_TAG: &str = "admin";

/// Maximum rows returned by export endpoints. Picked so a normal audit log fits in
/// one file even for noisy production deployments. If you're past 50k rows and
/// need more, use date ranges.
const EXPORT_LIMIT: i64 = 50_000;

#[derive(Deserialize)]
pub struct AuditLogParams {
    limit: Option<i64>,
    offset: Option<i64>,
    user_id: Option<Uuid>,
    actor_id: Option<Uuid>,
    /// Comma-separated list of event types to include. Unknown types are ignored.
    event_type: Option<String>,
    since: Option<i64>,
    until: Option<i64>,
}

/// Parse the comma-separated event_type param into a Vec, dropping any names the
/// server doesn't recognize. Unknown names are silently dropped so the admin
/// UI's filter dropdown never wedges the request if the enum drifts ahead of
/// the client.
fn parse_event_types(s: Option<&str>) -> Option<Vec<AuditEventType>> {
    let raw = s?;
    let types: Vec<AuditEventType> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(AuditEventType::from_str)
        .collect();
    if types.is_empty() { None } else { Some(types) }
}

fn build_query(params: &AuditLogParams) -> AuditLogQuery {
    let mut query = AuditLogQuery::new();
    if let Some(uid) = params.user_id {
        query = query.for_user(uid);
    }
    if let Some(aid) = params.actor_id {
        query = query.for_actor(aid);
    }
    if let Some(types) = parse_event_types(params.event_type.as_deref()) {
        query = query.event_types(types);
    }
    if let Some(ts) = params.since {
        query = query.since(ts);
    }
    if let Some(ts) = params.until {
        query = query.until(ts);
    }
    query
}

#[derive(Debug, Serialize)]
pub struct AuditLogResponse {
    pub entries: Vec<AuditLogRecord>,
    pub total: i64,
}

#[utoipa::path(
    get,
    path = "/api/audit",
    responses(
        (status = 200, description = "Audit log entries"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin required"),
    ),
    tag = ADMIN_TAG,
)]
pub async fn get_audit_log(
    _admin: AdminUser,
    State(state): State<AppState>,
    Query(params): Query<AuditLogParams>,
) -> Result<axum::Json<AuditLogResponse>, AppError> {
    let limit = params.limit.unwrap_or(50).clamp(1, 200);
    let offset = params.offset.unwrap_or(0).max(0);

    let base_query = build_query(&params);
    let mut conn = state.db_pool.acquire().await?;
    let total = base_query.count(&mut conn).await?;

    let paged = build_query(&params).limit(limit).offset(offset);
    let entries = paged.execute(&mut conn).await?;

    Ok(axum::Json(AuditLogResponse { entries, total }))
}

/// Expose the full list of event type names so the admin UI can populate its
/// filter dropdown without hardcoding. Ordering follows `AuditEventType::ALL`
/// for deterministic display.
#[utoipa::path(
    get,
    path = "/api/audit/event-types",
    responses(
        (status = 200, description = "All audit event types"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin required"),
    ),
    tag = ADMIN_TAG,
)]
pub async fn get_audit_event_types(
    _admin: AdminUser,
) -> axum::Json<Vec<&'static str>> {
    axum::Json(AuditEventType::ALL.iter().map(|t| t.as_str()).collect())
}

#[derive(Debug, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    #[default]
    Json,
    Csv,
}

#[derive(Deserialize)]
pub struct AuditExportParams {
    #[serde(default)]
    format: ExportFormat,
    user_id: Option<Uuid>,
    actor_id: Option<Uuid>,
    event_type: Option<String>,
    since: Option<i64>,
    until: Option<i64>,
}

impl AuditExportParams {
    fn to_list_params(&self) -> AuditLogParams {
        AuditLogParams {
            limit: None,
            offset: None,
            user_id: self.user_id,
            actor_id: self.actor_id,
            event_type: self.event_type.clone(),
            since: self.since,
            until: self.until,
        }
    }
}

/// Serialize a list of audit records as CSV. Columns are stable so downstream
/// pipelines can rely on the shape. Details/user_agent are quoted so embedded
/// commas/quotes/newlines don't break parsing.
pub fn records_to_csv(records: &[AuditLogRecord]) -> String {
    let mut out = String::from(
        "id,timestamp,event_type,user_id,username,actor_id,actor_username,ip_address,user_agent,details\n",
    );
    for r in records {
        out.push_str(&csv_field(&r.id.to_string()));
        out.push(',');
        out.push_str(&r.timestamp.to_string());
        out.push(',');
        out.push_str(&csv_field(&r.event_type));
        out.push(',');
        out.push_str(&csv_field(&r.user_id.map(|u| u.to_string()).unwrap_or_default()));
        out.push(',');
        out.push_str(&csv_field(r.username.as_deref().unwrap_or("")));
        out.push(',');
        out.push_str(&csv_field(&r.actor_id.map(|u| u.to_string()).unwrap_or_default()));
        out.push(',');
        out.push_str(&csv_field(r.actor_username.as_deref().unwrap_or("")));
        out.push(',');
        out.push_str(&csv_field(r.ip_address.as_deref().unwrap_or("")));
        out.push(',');
        out.push_str(&csv_field(r.user_agent.as_deref().unwrap_or("")));
        out.push(',');
        out.push_str(&csv_field(r.details.as_deref().unwrap_or("")));
        out.push('\n');
    }
    out
}

/// Quote a CSV field per RFC 4180: wrap in double quotes if it contains a comma,
/// newline, CR, or double-quote, and double any embedded double-quotes.
fn csv_field(value: &str) -> String {
    if value
        .chars()
        .any(|c| c == ',' || c == '\n' || c == '\r' || c == '"')
    {
        let escaped = value.replace('"', "\"\"");
        format!("\"{escaped}\"")
    } else {
        value.to_string()
    }
}

fn export_filename(format: &ExportFormat) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let ext = match format {
        ExportFormat::Json => "json",
        ExportFormat::Csv => "csv",
    };
    format!("authere-audit-{now}.{ext}")
}

#[utoipa::path(
    get,
    path = "/api/audit/export",
    responses(
        (status = 200, description = "Audit log export in the requested format"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin required"),
    ),
    tag = ADMIN_TAG,
)]
pub async fn export_audit_log(
    _admin: AdminUser,
    State(state): State<AppState>,
    Query(params): Query<AuditExportParams>,
) -> Result<axum::response::Response, AppError> {
    let list_params = params.to_list_params();
    let query = build_query(&list_params).limit(EXPORT_LIMIT);

    let mut conn = state.db_pool.acquire().await?;
    let records = query.execute(&mut conn).await?;

    let filename = export_filename(&params.format);
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
            .unwrap_or_else(|_| HeaderValue::from_static("attachment")),
    );

    match params.format {
        ExportFormat::Json => {
            headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
            let body = serde_json::to_string_pretty(&records)
                .map_err(|e| AppError::InternalError(format!("json serialize: {e}")))?;
            Ok((StatusCode::OK, headers, body).into_response())
        }
        ExportFormat::Csv => {
            headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/csv; charset=utf-8"));
            let body = records_to_csv(&records);
            Ok((StatusCode::OK, headers, body).into_response())
        }
    }
}

// ============================================================================
// Settings
// ============================================================================

#[utoipa::path(
    get,
    path = "/api/settings",
    responses(
        (status = 200, description = "Current system settings", body = SettingsResponse),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin required"),
    ),
    tag = ADMIN_TAG,
)]
pub async fn get_settings(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<axum::Json<SettingsResponse>, AppError> {
    let mut conn = state.db_pool.acquire().await?;
    let open_registration = open_registration_enabled(&mut conn).await?;
    let session_expiry = session_expiry_seconds(&mut conn).await?;
    let ldap_cfg = load_ldap_config(&mut conn).await?;
    Ok(axum::Json(SettingsResponse {
        open_registration,
        session_expiry_seconds: session_expiry,
        ldap: to_ldap_settings(&ldap_cfg),
    }))
}

#[utoipa::path(
    patch,
    path = "/api/settings",
    request_body(content = UpdateSettingsInput),
    responses(
        (status = 200, description = "Updated settings", body = SettingsResponse),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin required"),
    ),
    tag = ADMIN_TAG,
)]
pub async fn update_settings(
    State(state): State<AppState>,
    audit_ctx: AuditContext,
    admin: AdminUser,
    axum::extract::Json(input): axum::extract::Json<UpdateSettingsInput>,
) -> Result<axum::Json<SettingsResponse>, AppError> {
    let mut conn = state.db_pool.acquire().await?;

    let mut changes = serde_json::json!({});

    if let Some(open_reg) = input.open_registration {
        let val = if open_reg { "true" } else { "false" };
        set_setting(KEY_OPEN_REGISTRATION, val, &mut conn).await?;
        changes["open_registration"] = serde_json::json!(open_reg);
        info!(admin = %admin.0.user_id, open_registration = open_reg, "settings updated");
    }

    if let Some(expiry) = input.session_expiry_seconds {
        let validated = validate_session_expiry_seconds(expiry)
            .map_err(|e| AppError::InputError(vec![e]))?;
        set_setting(KEY_SESSION_EXPIRY_SECONDS, &validated.to_string(), &mut conn).await?;
        changes["session_expiry_seconds"] = serde_json::json!(validated);
        info!(admin = %admin.0.user_id, session_expiry_seconds = validated, "settings updated");
    }

    if let Some(ldap) = input.ldap {
        apply_ldap_input(&ldap, &mut changes, &mut conn).await?;
    }

    let _ = audit(AuditEventType::SettingsUpdated)
        .actor(admin.0.user_id)
        .ctx(&audit_ctx)
        .details(changes)
        .save(&mut conn)
        .await;

    let open_registration = open_registration_enabled(&mut conn).await?;
    let session_expiry = session_expiry_seconds(&mut conn).await?;
    let ldap_cfg = load_ldap_config(&mut conn).await?;
    Ok(axum::Json(SettingsResponse {
        open_registration,
        session_expiry_seconds: session_expiry,
        ldap: to_ldap_settings(&ldap_cfg),
    }))
}

async fn apply_ldap_input(
    input: &LdapSettingsInput,
    changes: &mut serde_json::Value,
    conn: &mut sqlx::SqliteConnection,
) -> Result<(), AppError> {
    let mut ldap_changes = serde_json::json!({});

    if let Some(enabled) = input.enabled {
        let val = if enabled { "true" } else { "false" };
        set_setting(KEY_LDAP_ENABLED, val, conn).await?;
        ldap_changes["enabled"] = serde_json::json!(enabled);
    }

    if let Some(ref base_dn) = input.base_dn {
        validate_base_dn(base_dn).map_err(|e| AppError::InputError(vec![e]))?;
        set_setting(KEY_LDAP_BASE_DN, base_dn.trim(), conn).await?;
        ldap_changes["base_dn"] = serde_json::json!(base_dn.trim());
    }

    if let Some(ref bind_address) = input.bind_address {
        validate_bind_address(bind_address).map_err(|e| AppError::InputError(vec![e]))?;
        set_setting(KEY_LDAP_BIND_ADDRESS, bind_address.trim(), conn).await?;
        ldap_changes["bind_address"] = serde_json::json!(bind_address.trim());
    }

    if let Some(mode) = input.password_mode {
        set_setting(KEY_LDAP_PASSWORD_MODE, mode.as_str(), conn).await?;
        ldap_changes["password_mode"] = serde_json::json!(mode.as_str());
    }

    if !ldap_changes.as_object().map(|o| o.is_empty()).unwrap_or(true) {
        changes["ldap"] = ldap_changes;
    }
    Ok(())
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RegenerateLdapPasswordResponse {
    pub password: String,
}

/// Generate a random service-account bind password, store its hash, and return the cleartext
/// once. Rotates any previously set password; active Jellyfin/other integrations will need to
/// be reconfigured.
#[utoipa::path(
    post,
    path = "/api/settings/ldap/regenerate-bind-password",
    responses(
        (status = 200, description = "New bind password, returned once", body = RegenerateLdapPasswordResponse),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin required"),
    ),
    tag = ADMIN_TAG,
)]
pub async fn regenerate_ldap_bind_password(
    State(state): State<AppState>,
    audit_ctx: AuditContext,
    admin: AdminUser,
) -> Result<axum::Json<RegenerateLdapPasswordResponse>, AppError> {
    let password = generate_service_password();
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
        .map_err(|e| AppError::InternalError(format!("Failed to hash password: {e}")))?
        .to_string();

    let mut conn = state.db_pool.acquire().await?;
    set_setting(KEY_LDAP_SERVICE_PASSWORD_HASH, &hash, &mut conn).await?;

    info!(admin = %admin.0.user_id, "ldap service bind password rotated");
    let _ = audit(AuditEventType::LdapBindPasswordRotated)
        .actor(admin.0.user_id)
        .ctx(&audit_ctx)
        .save(&mut conn)
        .await;

    Ok(axum::Json(RegenerateLdapPasswordResponse { password }))
}

fn generate_service_password() -> String {
    const CHARS: &[u8] =
        b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
    let mut rng = rand::thread_rng();
    (0..32)
        .map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char)
        .collect()
}

// ============================================================================
// Restart
// ============================================================================

#[utoipa::path(
    post,
    path = "/api/admin/restart",
    responses(
        (status = 202, description = "Restart initiated"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin required"),
    ),
    tag = ADMIN_TAG,
)]
pub async fn restart_service(
    State(state): State<AppState>,
    audit_ctx: AuditContext,
    admin: AdminUser,
) -> Result<StatusCode, AppError> {
    info!(admin = %admin.0.user_id, "admin-initiated service restart");

    let mut conn = state.db_pool.acquire().await?;
    let _ = audit(AuditEventType::SystemRestarted)
        .actor(admin.0.user_id)
        .ctx(&audit_ctx)
        .save(&mut conn)
        .await;
    drop(conn);

    let shutdown = state.shutdown.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        shutdown.notify_waiters();
    });

    Ok(StatusCode::ACCEPTED)
}

// ============================================================================
// Invitations
// ============================================================================

#[utoipa::path(
    get,
    path = "/api/invitations",
    responses(
        (status = 200, description = "List of invitations"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin required"),
    ),
    tag = ADMIN_TAG,
)]
pub async fn list_invitations(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<axum::Json<Vec<InvitationWithStatus>>, AppError> {
    let mut conn = state.db_pool.acquire().await?;
    let invitations = Invitation::list(&mut conn).await?;
    Ok(axum::Json(invitations))
}

#[utoipa::path(
    post,
    path = "/api/invitations",
    request_body(content = CreateInvitationInput),
    responses(
        (status = 201, description = "Created invitation"),
        (status = 400, description = "Invalid input"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin required"),
    ),
    tag = ADMIN_TAG,
)]
pub async fn create_invitation(
    State(state): State<AppState>,
    audit_ctx: AuditContext,
    admin: AdminUser,
    axum::extract::Json(input): axum::extract::Json<CreateInvitationInput>,
) -> Result<(StatusCode, axum::Json<Invitation>), AppError> {
    Invitation::validate_input(&input)?;

    let invitation = Invitation::new(input, admin.0.user_id);
    let mut conn = state.db_pool.acquire().await?;
    invitation.save(&mut conn).await?;

    info!(admin = %admin.0.user_id, invite_id = %invitation.id, label = ?invitation.label, "invitation created");
    let _ = audit(AuditEventType::InvitationCreated)
        .actor(admin.0.user_id)
        .ctx(&audit_ctx)
        .details(serde_json::json!({ "invite_id": invitation.id, "label": invitation.label }))
        .save(&mut conn)
        .await;

    Ok((StatusCode::CREATED, axum::Json(invitation)))
}

#[utoipa::path(
    delete,
    path = "/api/invitations/{id}",
    params(
        ("id" = String, Path, description = "Invitation ID")
    ),
    responses(
        (status = 204, description = "Invitation deleted"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Admin required"),
        (status = 404, description = "Invitation not found"),
    ),
    tag = ADMIN_TAG,
)]
pub async fn delete_invitation(
    State(state): State<AppState>,
    audit_ctx: AuditContext,
    admin: AdminUser,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    let mut conn = state.db_pool.acquire().await?;

    let deleted = Invitation::delete(&id, &mut conn).await?;
    if !deleted {
        return Err(AppError::NotFound);
    }

    info!(admin = %admin.0.user_id, invite_id = %id, "invitation deleted");
    let _ = audit(AuditEventType::InvitationDeleted)
        .actor(admin.0.user_id)
        .ctx(&audit_ctx)
        .details(serde_json::json!({ "invite_id": id }))
        .save(&mut conn)
        .await;

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditLogRecord;

    fn rec(details: Option<&str>, user_agent: Option<&str>) -> AuditLogRecord {
        AuditLogRecord {
            id: Uuid::nil(),
            timestamp: 1_700_000_000,
            event_type: "login_success".into(),
            user_id: Some(Uuid::nil()),
            actor_id: None,
            ip_address: Some("127.0.0.1".into()),
            user_agent: user_agent.map(Into::into),
            details: details.map(Into::into),
            username: Some("alice".into()),
            actor_username: None,
        }
    }

    #[test]
    fn parse_event_types_handles_absent() {
        assert!(parse_event_types(None).is_none());
        assert!(parse_event_types(Some("")).is_none());
        assert!(parse_event_types(Some(",,,")).is_none());
    }

    #[test]
    fn parse_event_types_returns_known_variants() {
        let got = parse_event_types(Some("login_success,login_failed")).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], AuditEventType::LoginSuccess);
        assert_eq!(got[1], AuditEventType::LoginFailed);
    }

    #[test]
    fn parse_event_types_skips_unknown_names() {
        let got = parse_event_types(Some("login_success,not_a_thing,logout")).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], AuditEventType::LoginSuccess);
        assert_eq!(got[1], AuditEventType::Logout);
    }

    #[test]
    fn parse_event_types_trims_whitespace() {
        let got = parse_event_types(Some(" login_success , logout ")).unwrap();
        assert_eq!(got.len(), 2);
    }

    #[test]
    fn parse_event_types_all_unknown_returns_none() {
        // If nothing parses, treat it as "no filter" rather than "match nothing",
        // otherwise a stale client hard-blocks itself from seeing any events.
        assert!(parse_event_types(Some("gibberish,more_gibberish")).is_none());
    }

    #[test]
    fn csv_field_quotes_values_containing_commas() {
        assert_eq!(csv_field("a,b"), "\"a,b\"");
    }

    #[test]
    fn csv_field_quotes_values_containing_newlines() {
        assert_eq!(csv_field("line1\nline2"), "\"line1\nline2\"");
        assert_eq!(csv_field("line1\r\nline2"), "\"line1\r\nline2\"");
    }

    #[test]
    fn csv_field_escapes_embedded_quotes() {
        assert_eq!(csv_field(r#"she said "hi""#), r#""she said ""hi""""#);
    }

    #[test]
    fn csv_field_leaves_plain_values_unquoted() {
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field(""), "");
    }

    #[test]
    fn records_to_csv_has_header_row() {
        let out = records_to_csv(&[]);
        assert!(out.starts_with(
            "id,timestamp,event_type,user_id,username,actor_id,actor_username,ip_address,user_agent,details\n"
        ));
    }

    #[test]
    fn records_to_csv_emits_one_line_per_record() {
        let out = records_to_csv(&[rec(None, Some("curl")), rec(None, Some("vitest"))]);
        // 1 header + 2 data rows = 3 newlines.
        assert_eq!(out.matches('\n').count(), 3);
        assert!(out.contains("curl"));
        assert!(out.contains("vitest"));
    }

    #[test]
    fn records_to_csv_quotes_details_with_commas() {
        let out = records_to_csv(&[rec(Some(r#"{"a":1,"b":2}"#), None)]);
        assert!(out.contains(r#""{""a"":1,""b"":2}""#));
    }

    #[test]
    fn export_filename_has_correct_extension() {
        assert!(export_filename(&ExportFormat::Json).ends_with(".json"));
        assert!(export_filename(&ExportFormat::Csv).ends_with(".csv"));
        assert!(export_filename(&ExportFormat::Json).starts_with("authere-audit-"));
    }

    #[test]
    fn build_query_applies_all_filters() {
        let params = AuditLogParams {
            limit: None,
            offset: None,
            user_id: Some(Uuid::nil()),
            actor_id: Some(Uuid::nil()),
            event_type: Some("login_success".into()),
            since: Some(100),
            until: Some(200),
        };
        // Smoke: just make sure this doesn't panic constructing the builder.
        let _ = build_query(&params);
    }
}

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;
use axum_extra::TypedHeader;
use headers::UserAgent;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::SqliteConnection;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::LazyLock;
use uuid::Uuid;

use crate::errors::AppError;

static TRUSTED_PROXIES: LazyLock<Vec<IpAddr>> = LazyLock::new(|| {
    std::env::var("AUTHERE_TRUSTED_PROXIES")
        .unwrap_or_default()
        .split(',')
        .filter_map(|s| s.trim().parse::<IpAddr>().ok())
        .collect()
});

/// Extract the real client IP from X-Forwarded-For, skipping trusted proxies from the right.
fn extract_client_ip(xff: Option<&str>, peer_ip: IpAddr) -> IpAddr {
    if TRUSTED_PROXIES.is_empty() {
        return peer_ip;
    }
    if !TRUSTED_PROXIES.contains(&peer_ip) {
        return peer_ip;
    }
    if let Some(xff) = xff {
        let addrs: Vec<&str> = xff.split(',').map(|s| s.trim()).collect();
        for addr_str in addrs.iter().rev() {
            if let Ok(addr) = addr_str.parse::<IpAddr>() {
                if !TRUSTED_PROXIES.contains(&addr) {
                    return addr;
                }
            }
        }
    }
    peer_ip
}

/// Request context for audit logging — IP address and user agent, extracted once per request.
///
/// `ip` is always an `IpAddr` (UNSPECIFIED if no peer info was available) so
/// rate limiters can use it as a bucket key. `ip_address` is the value we
/// actually persist to the audit log, and is `None` when there was no real
/// remote — recording `0.0.0.0` for an unknown peer would muddy the log.
#[derive(Debug, Clone)]
pub struct AuditContext {
    pub ip: IpAddr,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

impl<S: Send + Sync> FromRequestParts<S> for AuditContext {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let peer_ip = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip());

        let xff = parts
            .headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok());

        let (ip, ip_address) = match peer_ip {
            Some(p) => {
                let resolved = extract_client_ip(xff, p);
                (resolved, Some(resolved.to_string()))
            }
            None => (IpAddr::V4(Ipv4Addr::UNSPECIFIED), None),
        };

        let user_agent = TypedHeader::<UserAgent>::from_request_parts(parts, state)
            .await
            .ok()
            .map(|h| h.to_string());

        Ok(AuditContext {
            ip,
            ip_address,
            user_agent,
        })
    }
}

/// All audit event types. When adding a new variant, also add it to `as_str`,
/// `from_str`, and `ALL`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEventType {
    LoginSuccess,
    LoginFailed,
    Logout,
    TokenRefresh,
    UserCreated,
    UserUpdated,
    UserDeleted,
    PasswordChanged,
    RoleAssigned,
    RoleRemoved,
    MfaEnabled,
    MfaDisabled,
    // Admin-initiated actions
    AdminCreateUser,
    AdminUpdateUser,
    AdminDeleteUser,
    AdminPasswordReset,
    AdminRoleAssigned,
    AdminRoleRemoved,
    // Registration and invitations
    UserRegistered,
    InvitationCreated,
    InvitationDeleted,
    InvitationConsumed,
    SettingsUpdated,
    SystemRestarted,
    // LDAP
    LdapBindSuccess,
    LdapBindFailed,
    LdapBindRejectedMfaRequired,
    LdapBindPasswordRotated,
    // SCIM
    ScimTokenCreated,
    ScimTokenRevoked,
    ScimUserCreated,
    ScimUserUpdated,
    ScimUserDeactivated,
    ScimUserReactivated,
    ScimUserDeleted,
    // App passwords
    AppPasswordCreated,
    AppPasswordDeleted,
    AdminAppPasswordDeleted,
    // Application / OAuth clients
    ApplicationCreated,
    ApplicationUpdated,
    ApplicationDeleted,
    // OIDC provider
    OidcAuthorizeSuccess,
    OidcAuthorizeDenied,
    OidcTokenIssued,
    OidcTokenRejected,
    OidcUserinfoAccessed,
    OidcLogout,
    // Role definitions (separate from assignments)
    RoleCreated,
    RoleDeleted,
}

impl AuditEventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditEventType::LoginSuccess => "login_success",
            AuditEventType::LoginFailed => "login_failed",
            AuditEventType::Logout => "logout",
            AuditEventType::TokenRefresh => "token_refresh",
            AuditEventType::UserCreated => "user_created",
            AuditEventType::UserUpdated => "user_updated",
            AuditEventType::UserDeleted => "user_deleted",
            AuditEventType::PasswordChanged => "password_changed",
            AuditEventType::RoleAssigned => "role_assigned",
            AuditEventType::RoleRemoved => "role_removed",
            AuditEventType::MfaEnabled => "mfa_enabled",
            AuditEventType::MfaDisabled => "mfa_disabled",
            AuditEventType::AdminCreateUser => "admin_create_user",
            AuditEventType::AdminUpdateUser => "admin_update_user",
            AuditEventType::AdminDeleteUser => "admin_delete_user",
            AuditEventType::AdminPasswordReset => "admin_password_reset",
            AuditEventType::AdminRoleAssigned => "admin_role_assigned",
            AuditEventType::AdminRoleRemoved => "admin_role_removed",
            AuditEventType::UserRegistered => "user_registered",
            AuditEventType::InvitationCreated => "invitation_created",
            AuditEventType::InvitationDeleted => "invitation_deleted",
            AuditEventType::InvitationConsumed => "invitation_consumed",
            AuditEventType::SettingsUpdated => "settings_updated",
            AuditEventType::SystemRestarted => "system_restarted",
            AuditEventType::LdapBindSuccess => "ldap_bind_success",
            AuditEventType::LdapBindFailed => "ldap_bind_failed",
            AuditEventType::LdapBindRejectedMfaRequired => "ldap_bind_rejected_mfa_required",
            AuditEventType::LdapBindPasswordRotated => "ldap_bind_password_rotated",
            AuditEventType::ScimTokenCreated => "scim_token_created",
            AuditEventType::ScimTokenRevoked => "scim_token_revoked",
            AuditEventType::ScimUserCreated => "scim_user_created",
            AuditEventType::ScimUserUpdated => "scim_user_updated",
            AuditEventType::ScimUserDeactivated => "scim_user_deactivated",
            AuditEventType::ScimUserReactivated => "scim_user_reactivated",
            AuditEventType::ScimUserDeleted => "scim_user_deleted",
            AuditEventType::AppPasswordCreated => "app_password_created",
            AuditEventType::AppPasswordDeleted => "app_password_deleted",
            AuditEventType::AdminAppPasswordDeleted => "admin_app_password_deleted",
            AuditEventType::ApplicationCreated => "application_created",
            AuditEventType::ApplicationUpdated => "application_updated",
            AuditEventType::ApplicationDeleted => "application_deleted",
            AuditEventType::OidcAuthorizeSuccess => "oidc_authorize_success",
            AuditEventType::OidcAuthorizeDenied => "oidc_authorize_denied",
            AuditEventType::OidcTokenIssued => "oidc_token_issued",
            AuditEventType::OidcTokenRejected => "oidc_token_rejected",
            AuditEventType::OidcUserinfoAccessed => "oidc_userinfo_accessed",
            AuditEventType::OidcLogout => "oidc_logout",
            AuditEventType::RoleCreated => "role_created",
            AuditEventType::RoleDeleted => "role_deleted",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        Self::ALL.iter().find(|t| t.as_str() == s).copied()
    }

    /// Full list of event types, used for the `from_str` lookup and the admin UI
    /// filter dropdown (exposed via `GET /api/audit/event-types`).
    pub const ALL: &'static [AuditEventType] = &[
        AuditEventType::LoginSuccess,
        AuditEventType::LoginFailed,
        AuditEventType::Logout,
        AuditEventType::TokenRefresh,
        AuditEventType::UserCreated,
        AuditEventType::UserUpdated,
        AuditEventType::UserDeleted,
        AuditEventType::PasswordChanged,
        AuditEventType::RoleAssigned,
        AuditEventType::RoleRemoved,
        AuditEventType::MfaEnabled,
        AuditEventType::MfaDisabled,
        AuditEventType::AdminCreateUser,
        AuditEventType::AdminUpdateUser,
        AuditEventType::AdminDeleteUser,
        AuditEventType::AdminPasswordReset,
        AuditEventType::AdminRoleAssigned,
        AuditEventType::AdminRoleRemoved,
        AuditEventType::UserRegistered,
        AuditEventType::InvitationCreated,
        AuditEventType::InvitationDeleted,
        AuditEventType::InvitationConsumed,
        AuditEventType::SettingsUpdated,
        AuditEventType::SystemRestarted,
        AuditEventType::LdapBindSuccess,
        AuditEventType::LdapBindFailed,
        AuditEventType::LdapBindRejectedMfaRequired,
        AuditEventType::LdapBindPasswordRotated,
        AuditEventType::ScimTokenCreated,
        AuditEventType::ScimTokenRevoked,
        AuditEventType::ScimUserCreated,
        AuditEventType::ScimUserUpdated,
        AuditEventType::ScimUserDeactivated,
        AuditEventType::ScimUserReactivated,
        AuditEventType::ScimUserDeleted,
        AuditEventType::AppPasswordCreated,
        AuditEventType::AppPasswordDeleted,
        AuditEventType::AdminAppPasswordDeleted,
        AuditEventType::ApplicationCreated,
        AuditEventType::ApplicationUpdated,
        AuditEventType::ApplicationDeleted,
        AuditEventType::OidcAuthorizeSuccess,
        AuditEventType::OidcAuthorizeDenied,
        AuditEventType::OidcTokenIssued,
        AuditEventType::OidcTokenRejected,
        AuditEventType::OidcUserinfoAccessed,
        AuditEventType::OidcLogout,
        AuditEventType::RoleCreated,
        AuditEventType::RoleDeleted,
    ];
}

/// Builder for creating audit log entries.
///
/// Most producers will use the `audit()` free function, which is a shorter
/// alias for `AuditLogEntry::new(event_type)`:
///
/// ```ignore
/// let _ = audit(AuditEventType::LoginSuccess)
///     .user(user_id)
///     .ctx(&audit_ctx)
///     .save(&mut conn)
///     .await;
/// ```
pub struct AuditLogEntry {
    event_type: AuditEventType,
    user_id: Option<Uuid>,
    actor_id: Option<Uuid>,
    ip_address: Option<String>,
    user_agent: Option<String>,
    details: Option<serde_json::Value>,
}

impl AuditLogEntry {
    pub fn new(event_type: AuditEventType) -> Self {
        Self {
            event_type,
            user_id: None,
            actor_id: None,
            ip_address: None,
            user_agent: None,
            details: None,
        }
    }

    /// The user this event is about (e.g., the user who logged in)
    pub fn user(mut self, user_id: Uuid) -> Self {
        self.user_id = Some(user_id);
        self
    }

    /// The actor who performed the action (e.g., admin who changed a role). Pass
    /// `Option<Uuid>` and the builder will skip when `None` — convenient for
    /// self-service flows where there may or may not be an acting admin.
    pub fn actor<A: IntoActorId>(mut self, actor: A) -> Self {
        if let Some(id) = actor.into_actor_id() {
            self.actor_id = Some(id);
        }
        self
    }

    /// Pull IP and user-agent from an HTTP request's audit context. This is the
    /// one-call replacement for `.ip(&ctx.ip_address).user_agent(ua)` that most
    /// producers used to repeat. The IP is forwarded only when the request
    /// actually had a remote peer; otherwise the audit row's `ip_address`
    /// stays NULL rather than recording a fake address.
    pub fn ctx(mut self, ctx: &AuditContext) -> Self {
        if let Some(ref ip) = ctx.ip_address {
            self.ip_address = Some(ip.clone());
        }
        if let Some(ref ua) = ctx.user_agent {
            self.user_agent = Some(ua.clone());
        }
        self
    }

    /// Client IP address. Prefer `.ctx()` when called from an HTTP handler;
    /// use `.ip()` only for non-HTTP producers like the LDAP server.
    pub fn ip(mut self, ip: impl Into<String>) -> Self {
        self.ip_address = Some(ip.into());
        self
    }

    /// Client user agent
    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    /// Additional details as JSON
    pub fn details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    /// Save the audit log entry to the database
    pub async fn save(self, conn: &mut SqliteConnection) -> Result<(), AppError> {
        let id = Uuid::now_v7();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs() as i64;
        let event_type = self.event_type.as_str();
        let details = self.details.map(|d| d.to_string());

        sqlx::query!(
            r#"INSERT INTO audit_log (id, timestamp, event_type, user_id, actor_id, ip_address, user_agent, details)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)"#,
            id,
            timestamp,
            event_type,
            self.user_id,
            self.actor_id,
            self.ip_address,
            self.user_agent,
            details
        )
        .execute(conn)
        .await?;

        Ok(())
    }
}

/// Short alias for `AuditLogEntry::new(event_type)`. Most call sites should use
/// this; the plain builder constructor is kept for callers that need it.
pub fn audit(event_type: AuditEventType) -> AuditLogEntry {
    AuditLogEntry::new(event_type)
}

/// Polymorphic `.actor()` input: accepts `Uuid` or `Option<Uuid>` so handlers can
/// pass `Option` from self-service flows without an outer `if let`.
pub trait IntoActorId {
    fn into_actor_id(self) -> Option<Uuid>;
}

impl IntoActorId for Uuid {
    fn into_actor_id(self) -> Option<Uuid> {
        Some(self)
    }
}

impl IntoActorId for Option<Uuid> {
    fn into_actor_id(self) -> Option<Uuid> {
        self
    }
}

/// Query audit logs with optional filters
#[derive(Debug, Default)]
pub struct AuditLogQuery {
    user_id: Option<Uuid>,
    actor_id: Option<Uuid>,
    event_types: Option<Vec<AuditEventType>>,
    since: Option<i64>,
    until: Option<i64>,
    limit: Option<i64>,
    offset: Option<i64>,
}

impl AuditLogQuery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn for_user(mut self, user_id: Uuid) -> Self {
        self.user_id = Some(user_id);
        self
    }

    pub fn for_actor(mut self, actor_id: Uuid) -> Self {
        self.actor_id = Some(actor_id);
        self
    }

    pub fn event_types(mut self, types: Vec<AuditEventType>) -> Self {
        self.event_types = Some(types);
        self
    }

    pub fn since(mut self, timestamp: i64) -> Self {
        self.since = Some(timestamp);
        self
    }

    pub fn until(mut self, timestamp: i64) -> Self {
        self.until = Some(timestamp);
        self
    }

    pub fn limit(mut self, limit: i64) -> Self {
        self.limit = Some(limit);
        self
    }

    pub fn offset(mut self, offset: i64) -> Self {
        self.offset = Some(offset);
        self
    }

    /// Push the shared WHERE clause on to a QueryBuilder. Used by both the
    /// row-fetching query and the matching-count query so the two can't drift.
    fn push_filters<'q>(&'q self, qb: &mut sqlx::QueryBuilder<'q, sqlx::Sqlite>) {
        if let Some(uid) = self.user_id {
            qb.push(" AND al.user_id = ").push_bind(uid);
        }
        if let Some(aid) = self.actor_id {
            qb.push(" AND al.actor_id = ").push_bind(aid);
        }
        if let Some(ref types) = self.event_types {
            if !types.is_empty() {
                qb.push(" AND al.event_type IN (");
                let mut sep = qb.separated(", ");
                for t in types {
                    sep.push_bind(t.as_str());
                }
                qb.push(")");
            }
        }
        if let Some(ts) = self.since {
            qb.push(" AND al.timestamp >= ").push_bind(ts);
        }
        if let Some(ts) = self.until {
            qb.push(" AND al.timestamp <= ").push_bind(ts);
        }
    }

    pub async fn execute(
        &self,
        conn: &mut SqliteConnection,
    ) -> Result<Vec<AuditLogRecord>, AppError> {
        let mut qb: sqlx::QueryBuilder<sqlx::Sqlite> = sqlx::QueryBuilder::new(
            "SELECT al.id, al.timestamp, al.event_type, al.user_id, al.actor_id, \
             al.ip_address, al.user_agent, al.details, \
             u.username as username, actor.username as actor_username \
             FROM audit_log al \
             LEFT JOIN users u ON al.user_id = u.id \
             LEFT JOIN users actor ON al.actor_id = actor.id \
             WHERE 1=1",
        );

        self.push_filters(&mut qb);
        qb.push(" ORDER BY al.timestamp DESC");

        if let Some(limit) = self.limit {
            qb.push(" LIMIT ").push_bind(limit);
        }
        if let Some(offset) = self.offset {
            qb.push(" OFFSET ").push_bind(offset);
        }

        Ok(qb.build_query_as().fetch_all(conn).await?)
    }

    /// Count rows matching the current filters. Ignores limit/offset.
    pub async fn count(&self, conn: &mut SqliteConnection) -> Result<i64, AppError> {
        let mut qb: sqlx::QueryBuilder<sqlx::Sqlite> =
            sqlx::QueryBuilder::new("SELECT COUNT(*) FROM audit_log al WHERE 1=1");
        self.push_filters(&mut qb);
        let count: i64 = qb.build_query_scalar().fetch_one(conn).await?;
        Ok(count)
    }
}

fn serialize_json_string<S>(value: &Option<String>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match value {
        None => serializer.serialize_none(),
        Some(s) => match serde_json::from_str::<serde_json::Value>(s) {
            Ok(v) => v.serialize(serializer),
            Err(_) => serializer.serialize_str(s),
        },
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuditLogRecord {
    pub id: Uuid,
    pub timestamp: i64,
    pub event_type: String,
    pub user_id: Option<Uuid>,
    pub actor_id: Option<Uuid>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    #[serde(serialize_with = "serialize_json_string")]
    pub details: Option<String>,
    /// Resolved username for user_id (None if user was deleted)
    #[sqlx(default)]
    pub username: Option<String>,
    /// Resolved username for actor_id (None if actor was deleted)
    #[sqlx(default)]
    pub actor_username: Option<String>,
}

/// Log a login failure. Pass user_id if the user account exists (wrong password);
/// leave None for unknown usernames. Kept as a helper because the details JSON
/// needs to mark nonexistent users — doing this inline at every call site would
/// be easy to get wrong.
pub async fn log_login_failed(
    username: &str,
    user_id: Option<Uuid>,
    ctx: &AuditContext,
    conn: &mut SqliteConnection,
) -> Result<(), AppError> {
    let details = if user_id.is_some() {
        json!({ "username": username })
    } else {
        json!({ "username": username, "user_exists": false })
    };

    let mut entry = audit(AuditEventType::LoginFailed).ctx(ctx).details(details);
    if let Some(uid) = user_id {
        entry = entry.user(uid);
    }
    entry.save(conn).await
}

/// Log a successful LDAP simple-bind. Called from the LDAP server (no HTTP
/// request), so it takes raw IP rather than an `AuditContext`.
pub async fn log_ldap_bind_success(
    user_id: Option<Uuid>,
    dn: &str,
    ip: &str,
    mode: &str,
    credential: &str,
    conn: &mut SqliteConnection,
) -> Result<(), AppError> {
    let mut entry = audit(AuditEventType::LdapBindSuccess)
        .ip(ip)
        .details(json!({ "dn": dn, "mode": mode, "credential": credential }));
    if let Some(uid) = user_id {
        entry = entry.user(uid);
    }
    entry.save(conn).await
}

/// Log a failed LDAP bind. `reason` is a short machine-readable tag,
/// e.g. "invalid_credentials".
pub async fn log_ldap_bind_failed(
    user_id: Option<Uuid>,
    dn: &str,
    ip: &str,
    mode: &str,
    reason: &str,
    conn: &mut SqliteConnection,
) -> Result<(), AppError> {
    let mut entry = audit(AuditEventType::LdapBindFailed)
        .ip(ip)
        .details(json!({ "dn": dn, "mode": mode, "reason": reason }));
    if let Some(uid) = user_id {
        entry = entry.user(uid);
    }
    entry.save(conn).await
}

/// Log an LDAP bind rejected because the user has TOTP enabled and the active
/// mode cannot accept an MFA second factor over simple bind.
pub async fn log_ldap_bind_rejected_mfa_required(
    user_id: Uuid,
    dn: &str,
    ip: &str,
    mode: &str,
    conn: &mut SqliteConnection,
) -> Result<(), AppError> {
    audit(AuditEventType::LdapBindRejectedMfaRequired)
        .user(user_id)
        .ip(ip)
        .details(json!({ "dn": dn, "mode": mode }))
        .save(conn)
        .await
}

/// Build the details block for SCIM events — token identity is included on every
/// SCIM mutation so admins can trace downstream user changes back to a specific
/// integration ("Okta prod" vs. "Azure").
pub fn scim_details(
    token_id: Uuid,
    token_name: &str,
    extra: Option<serde_json::Value>,
) -> serde_json::Value {
    match extra {
        None => json!({ "scim_token_id": token_id, "scim_token_name": token_name }),
        Some(serde_json::Value::Object(mut map)) => {
            map.insert("scim_token_id".into(), json!(token_id));
            map.insert("scim_token_name".into(), json!(token_name));
            serde_json::Value::Object(map)
        }
        Some(other) => {
            json!({ "scim_token_id": token_id, "scim_token_name": token_name, "extra": other })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_type_as_str() {
        assert_eq!(AuditEventType::LoginSuccess.as_str(), "login_success");
        assert_eq!(AuditEventType::LoginFailed.as_str(), "login_failed");
        assert_eq!(AuditEventType::Logout.as_str(), "logout");
        assert_eq!(AuditEventType::TokenRefresh.as_str(), "token_refresh");
        assert_eq!(AuditEventType::UserCreated.as_str(), "user_created");
        assert_eq!(AuditEventType::AppPasswordCreated.as_str(), "app_password_created");
        assert_eq!(AuditEventType::ApplicationDeleted.as_str(), "application_deleted");
        assert_eq!(AuditEventType::RoleCreated.as_str(), "role_created");
        assert_eq!(AuditEventType::SystemRestarted.as_str(), "system_restarted");
    }

    #[test]
    fn all_list_covers_every_variant() {
        // If someone adds a new event type but forgets to add it to ALL,
        // from_str will miss it. Spot-check that the list is fully populated
        // by round-tripping every known name.
        for variant in AuditEventType::ALL {
            let s = variant.as_str();
            assert_eq!(AuditEventType::from_str(s), Some(*variant), "round-trip failed for {s}");
        }
    }

    #[test]
    fn from_str_unknown_returns_none() {
        assert_eq!(AuditEventType::from_str("not_a_real_event"), None);
        assert_eq!(AuditEventType::from_str(""), None);
    }

    #[test]
    fn builder_applies_ctx_ip_and_user_agent() {
        let ctx = AuditContext {
            ip: "10.0.0.5".parse().unwrap(),
            ip_address: Some("10.0.0.5".into()),
            user_agent: Some("Mozilla/5.0".into()),
        };
        let entry = audit(AuditEventType::LoginSuccess).ctx(&ctx);
        assert_eq!(entry.ip_address.as_deref(), Some("10.0.0.5"));
        assert_eq!(entry.user_agent.as_deref(), Some("Mozilla/5.0"));
    }

    #[test]
    fn builder_ctx_without_user_agent_leaves_field_empty() {
        let ctx = AuditContext {
            ip: "127.0.0.1".parse().unwrap(),
            ip_address: Some("127.0.0.1".into()),
            user_agent: None,
        };
        let entry = audit(AuditEventType::Logout).ctx(&ctx);
        assert_eq!(entry.ip_address.as_deref(), Some("127.0.0.1"));
        assert!(entry.user_agent.is_none());
    }

    #[test]
    fn builder_ctx_without_peer_ip_records_no_ip() {
        // No ConnectInfo at extraction time → no real remote IP. The audit row's
        // ip_address stays NULL rather than getting a fake "0.0.0.0".
        let ctx = AuditContext {
            ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            ip_address: None,
            user_agent: None,
        };
        let entry = audit(AuditEventType::SystemRestarted).ctx(&ctx);
        assert!(entry.ip_address.is_none());
    }

    #[test]
    fn actor_accepts_option_none() {
        let entry = audit(AuditEventType::UserCreated).actor(None::<Uuid>);
        assert!(entry.actor_id.is_none());
    }

    #[test]
    fn actor_accepts_option_some() {
        let id = Uuid::now_v7();
        let entry = audit(AuditEventType::UserCreated).actor(Some(id));
        assert_eq!(entry.actor_id, Some(id));
    }

    #[test]
    fn actor_accepts_raw_uuid() {
        let id = Uuid::now_v7();
        let entry = audit(AuditEventType::AdminUpdateUser).actor(id);
        assert_eq!(entry.actor_id, Some(id));
    }

    #[test]
    fn test_audit_log_entry_builder() {
        let user_id = Uuid::now_v7();
        let actor_id = Uuid::now_v7();

        let entry = audit(AuditEventType::AdminRoleAssigned)
            .user(user_id)
            .actor(actor_id)
            .ip("192.168.1.1")
            .user_agent("Mozilla/5.0")
            .details(json!({ "role": "admin" }));

        assert_eq!(entry.event_type, AuditEventType::AdminRoleAssigned);
        assert_eq!(entry.user_id, Some(user_id));
        assert_eq!(entry.actor_id, Some(actor_id));
        assert_eq!(entry.ip_address, Some("192.168.1.1".to_string()));
        assert_eq!(entry.user_agent, Some("Mozilla/5.0".to_string()));
        assert!(entry.details.is_some());
    }

    #[test]
    fn scim_details_merges_extra_object() {
        let token_id = Uuid::nil();
        let extra = json!({ "fields_changed": ["email"] });
        let merged = scim_details(token_id, "Okta prod", Some(extra));
        let obj = merged.as_object().unwrap();
        assert_eq!(obj["scim_token_id"], json!(token_id));
        assert_eq!(obj["scim_token_name"], "Okta prod");
        assert_eq!(obj["fields_changed"], json!(["email"]));
    }

    #[test]
    fn scim_details_wraps_non_object_extra() {
        let token_id = Uuid::nil();
        let merged = scim_details(token_id, "Azure", Some(json!("raw-string")));
        let obj = merged.as_object().unwrap();
        assert_eq!(obj["extra"], json!("raw-string"));
    }

    #[test]
    fn scim_details_without_extra_only_has_token_fields() {
        let token_id = Uuid::nil();
        let merged = scim_details(token_id, "OneLogin", None);
        let obj = merged.as_object().unwrap();
        assert_eq!(obj.len(), 2);
        assert!(obj.contains_key("scim_token_id"));
        assert!(obj.contains_key("scim_token_name"));
    }

    #[test]
    fn test_entry_builder_defaults() {
        let entry = audit(AuditEventType::Logout);
        assert_eq!(entry.event_type, AuditEventType::Logout);
        assert!(entry.user_id.is_none());
        assert!(entry.actor_id.is_none());
        assert!(entry.ip_address.is_none());
        assert!(entry.user_agent.is_none());
        assert!(entry.details.is_none());
    }

    #[test]
    fn test_entry_builder_chaining() {
        let uid = Uuid::now_v7();
        let entry = audit(AuditEventType::LoginSuccess).user(uid).ip("10.0.0.1");

        assert_eq!(entry.user_id, Some(uid));
        assert_eq!(entry.ip_address, Some("10.0.0.1".to_string()));
        assert!(entry.actor_id.is_none());
    }

    #[test]
    fn test_audit_log_query_builder() {
        let uid = Uuid::now_v7();
        let aid = Uuid::now_v7();
        let query = AuditLogQuery::new()
            .for_user(uid)
            .for_actor(aid)
            .since(1000)
            .until(2000)
            .limit(50)
            .offset(10);

        assert_eq!(query.user_id, Some(uid));
        assert_eq!(query.actor_id, Some(aid));
        assert_eq!(query.since, Some(1000));
        assert_eq!(query.until, Some(2000));
        assert_eq!(query.limit, Some(50));
        assert_eq!(query.offset, Some(10));
    }

    #[test]
    fn test_audit_log_query_defaults() {
        let query = AuditLogQuery::new();
        assert!(query.user_id.is_none());
        assert!(query.actor_id.is_none());
        assert!(query.event_types.is_none());
        assert!(query.since.is_none());
        assert!(query.until.is_none());
        assert!(query.limit.is_none());
        assert!(query.offset.is_none());
    }

    #[test]
    fn test_audit_log_query_event_types() {
        let query = AuditLogQuery::new().event_types(vec![
            AuditEventType::LoginSuccess,
            AuditEventType::LoginFailed,
        ]);
        let types = query.event_types.as_ref().unwrap();
        assert_eq!(types.len(), 2);
        assert_eq!(types[0], AuditEventType::LoginSuccess);
        assert_eq!(types[1], AuditEventType::LoginFailed);
    }

    #[test]
    fn test_serialize_json_string_none() {
        let val: Option<String> = None;
        let result = serde_json::to_string(&SerHelper(&val)).unwrap();
        assert_eq!(result, "null");
    }

    #[test]
    fn test_serialize_json_string_valid_json() {
        let val = Some(r#"{"key":"value"}"#.to_string());
        let result = serde_json::to_string(&SerHelper(&val)).unwrap();
        assert_eq!(result, r#"{"key":"value"}"#);
    }

    #[test]
    fn test_serialize_json_string_plain_string() {
        let val = Some("not-json".to_string());
        let result = serde_json::to_string(&SerHelper(&val)).unwrap();
        assert_eq!(result, r#""not-json""#);
    }

    struct SerHelper<'a>(&'a Option<String>);
    impl serde::Serialize for SerHelper<'_> {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serialize_json_string(self.0, serializer)
        }
    }

    #[test]
    fn test_audit_log_record_serialization() {
        let record = AuditLogRecord {
            id: Uuid::nil(),
            timestamp: 1700000000,
            event_type: "login_success".into(),
            user_id: Some(Uuid::nil()),
            actor_id: None,
            ip_address: Some("127.0.0.1".into()),
            user_agent: Some("test".into()),
            details: Some(r#"{"foo":"bar"}"#.into()),
            username: Some("testuser".into()),
            actor_username: None,
        };

        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("login_success"));
        assert!(json.contains("127.0.0.1"));
        assert!(json.contains("testuser"));
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["details"]["foo"], "bar");
    }

    #[test]
    fn test_extract_client_ip_no_proxies() {
        let peer = "192.168.1.100".parse().unwrap();
        let result = extract_client_ip(Some("10.0.0.1"), peer);
        assert_eq!(result, peer);
    }

    #[test]
    fn test_audit_context_default_ip() {
        let ctx = AuditContext {
            ip: "127.0.0.1".parse().unwrap(),
            ip_address: Some("127.0.0.1".into()),
            user_agent: None,
        };
        assert_eq!(ctx.ip_address.as_deref(), Some("127.0.0.1"));
        assert!(ctx.user_agent.is_none());
    }
}

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
#[derive(Debug, Clone)]
pub struct AuditContext {
    pub ip: IpAddr,
    pub ip_address: String,
    pub user_agent: Option<String>,
}

impl<S: Send + Sync> FromRequestParts<S> for AuditContext {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let peer_ip = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip())
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));

        let xff = parts
            .headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok());

        let ip = extract_client_ip(xff, peer_ip);

        let user_agent = TypedHeader::<UserAgent>::from_request_parts(parts, state)
            .await
            .ok()
            .map(|h| h.to_string());

        Ok(AuditContext {
            ip,
            ip_address: ip.to_string(),
            user_agent,
        })
    }
}

/// Types of audit events
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
        }
    }
}

/// Builder for creating audit log entries
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

    /// The actor who performed the action (e.g., admin who changed a role)
    pub fn actor(mut self, actor_id: Uuid) -> Self {
        self.actor_id = Some(actor_id);
        self
    }

    /// Client IP address
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

/// Query audit logs with optional filters
#[derive(Debug, Default)]
pub struct AuditLogQuery {
    user_id: Option<Uuid>,
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

    pub async fn execute(self, conn: &mut SqliteConnection) -> Result<Vec<AuditLogRecord>, AppError> {
        let mut qb: sqlx::QueryBuilder<sqlx::Sqlite> = sqlx::QueryBuilder::new(
            "SELECT al.id, al.timestamp, al.event_type, al.user_id, al.actor_id, \
             al.ip_address, al.user_agent, al.details, \
             u.username as username, actor.username as actor_username \
             FROM audit_log al \
             LEFT JOIN users u ON al.user_id = u.id \
             LEFT JOIN users actor ON al.actor_id = actor.id \
             WHERE 1=1",
        );

        if let Some(uid) = self.user_id {
            qb.push(" AND al.user_id = ").push_bind(uid);
        }
        if let Some(ts) = self.since {
            qb.push(" AND al.timestamp >= ").push_bind(ts);
        }
        if let Some(ts) = self.until {
            qb.push(" AND al.timestamp <= ").push_bind(ts);
        }

        qb.push(" ORDER BY al.timestamp DESC");

        if let Some(limit) = self.limit {
            qb.push(" LIMIT ").push_bind(limit);
        }
        if let Some(offset) = self.offset {
            qb.push(" OFFSET ").push_bind(offset);
        }

        Ok(qb.build_query_as().fetch_all(conn).await?)
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

/// Convenience function to log a login success
pub async fn log_login_success(
    user_id: Uuid,
    ctx: &AuditContext,
    conn: &mut SqliteConnection,
) -> Result<(), AppError> {
    let mut entry = AuditLogEntry::new(AuditEventType::LoginSuccess)
        .user(user_id)
        .ip(&ctx.ip_address);

    if let Some(ref ua) = ctx.user_agent {
        entry = entry.user_agent(ua);
    }

    entry.save(conn).await
}

/// Convenience function to log a login failure.
/// Pass user_id if the user account exists (wrong password); leave None for unknown usernames.
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

    let mut entry = AuditLogEntry::new(AuditEventType::LoginFailed)
        .ip(&ctx.ip_address)
        .details(details);

    if let Some(uid) = user_id {
        entry = entry.user(uid);
    }

    if let Some(ref ua) = ctx.user_agent {
        entry = entry.user_agent(ua);
    }

    entry.save(conn).await
}

/// Convenience function to log a logout
pub async fn log_logout(
    user_id: Uuid,
    ctx: &AuditContext,
    conn: &mut SqliteConnection,
) -> Result<(), AppError> {
    AuditLogEntry::new(AuditEventType::Logout)
        .user(user_id)
        .ip(&ctx.ip_address)
        .save(conn)
        .await
}

/// Convenience function to log a token refresh
pub async fn log_token_refresh(
    user_id: Uuid,
    ctx: &AuditContext,
    conn: &mut SqliteConnection,
) -> Result<(), AppError> {
    AuditLogEntry::new(AuditEventType::TokenRefresh)
        .user(user_id)
        .ip(&ctx.ip_address)
        .save(conn)
        .await
}

/// Convenience function to log user creation (self-registration)
pub async fn log_user_created(
    user_id: Uuid,
    actor_id: Option<Uuid>,
    ctx: &AuditContext,
    conn: &mut SqliteConnection,
) -> Result<(), AppError> {
    let mut entry = AuditLogEntry::new(AuditEventType::UserCreated)
        .user(user_id)
        .ip(&ctx.ip_address);

    if let Some(actor) = actor_id {
        entry = entry.actor(actor);
    }

    entry.save(conn).await
}

/// Convenience function to log a self-service password change or admin password reset
pub async fn log_password_changed(
    user_id: Uuid,
    actor_id: Option<Uuid>,
    ctx: &AuditContext,
    conn: &mut SqliteConnection,
) -> Result<(), AppError> {
    let event_type = if actor_id.is_some() {
        AuditEventType::AdminPasswordReset
    } else {
        AuditEventType::PasswordChanged
    };

    let mut entry = AuditLogEntry::new(event_type)
        .user(user_id)
        .ip(&ctx.ip_address);

    if let Some(actor) = actor_id {
        entry = entry.actor(actor);
    }

    entry.save(conn).await
}

/// Log an admin updating a user's profile
pub async fn log_admin_update_user(
    user_id: Uuid,
    actor_id: Uuid,
    ctx: &AuditContext,
    conn: &mut SqliteConnection,
) -> Result<(), AppError> {
    AuditLogEntry::new(AuditEventType::AdminUpdateUser)
        .user(user_id)
        .actor(actor_id)
        .ip(&ctx.ip_address)
        .save(conn)
        .await
}

/// Log an admin assigning a role to a user
pub async fn log_admin_role_assigned(
    user_id: Uuid,
    actor_id: Uuid,
    role_id: Uuid,
    role_name: &str,
    ctx: &AuditContext,
    conn: &mut SqliteConnection,
) -> Result<(), AppError> {
    AuditLogEntry::new(AuditEventType::AdminRoleAssigned)
        .user(user_id)
        .actor(actor_id)
        .ip(&ctx.ip_address)
        .details(json!({ "role_id": role_id, "role_name": role_name }))
        .save(conn)
        .await
}

/// Log an admin removing a role from a user
pub async fn log_admin_role_removed(
    user_id: Uuid,
    actor_id: Uuid,
    role_id: Uuid,
    ctx: &AuditContext,
    conn: &mut SqliteConnection,
) -> Result<(), AppError> {
    AuditLogEntry::new(AuditEventType::AdminRoleRemoved)
        .user(user_id)
        .actor(actor_id)
        .ip(&ctx.ip_address)
        .details(json!({ "role_id": role_id }))
        .save(conn)
        .await
}

/// Log a user self-registration
pub async fn log_user_registered(
    user_id: Uuid,
    invite_id: Option<&str>,
    ctx: &AuditContext,
    conn: &mut SqliteConnection,
) -> Result<(), AppError> {
    let details = if let Some(id) = invite_id {
        json!({ "invite_used": true, "invite_id": id })
    } else {
        json!({ "invite_used": false })
    };
    AuditLogEntry::new(AuditEventType::UserRegistered)
        .user(user_id)
        .ip(&ctx.ip_address)
        .details(details)
        .save(conn)
        .await
}

/// Log an admin creating an invitation
pub async fn log_invitation_created(
    actor_id: Uuid,
    invite_id: &str,
    label: Option<&str>,
    ctx: &AuditContext,
    conn: &mut SqliteConnection,
) -> Result<(), AppError> {
    AuditLogEntry::new(AuditEventType::InvitationCreated)
        .actor(actor_id)
        .ip(&ctx.ip_address)
        .details(json!({ "invite_id": invite_id, "label": label }))
        .save(conn)
        .await
}

/// Log an admin deleting an invitation
pub async fn log_invitation_deleted(
    actor_id: Uuid,
    invite_id: &str,
    ctx: &AuditContext,
    conn: &mut SqliteConnection,
) -> Result<(), AppError> {
    AuditLogEntry::new(AuditEventType::InvitationDeleted)
        .actor(actor_id)
        .ip(&ctx.ip_address)
        .details(json!({ "invite_id": invite_id }))
        .save(conn)
        .await
}

/// Log an invitation being consumed during registration
pub async fn log_invitation_consumed(
    user_id: Uuid,
    invite_id: &str,
    ctx: &AuditContext,
    conn: &mut SqliteConnection,
) -> Result<(), AppError> {
    AuditLogEntry::new(AuditEventType::InvitationConsumed)
        .user(user_id)
        .ip(&ctx.ip_address)
        .details(json!({ "invite_id": invite_id }))
        .save(conn)
        .await
}

/// Log a successful LDAP simple-bind. Sets user_id when bound as a user (not the service
/// account), and tags the event with the password mode and credential kind used.
pub async fn log_ldap_bind_success(
    user_id: Option<Uuid>,
    dn: &str,
    ip: &str,
    mode: &str,
    credential: &str,
    conn: &mut SqliteConnection,
) -> Result<(), AppError> {
    let mut entry = AuditLogEntry::new(AuditEventType::LdapBindSuccess)
        .ip(ip)
        .details(json!({ "dn": dn, "mode": mode, "credential": credential }));
    if let Some(uid) = user_id {
        entry = entry.user(uid);
    }
    entry.save(conn).await
}

/// Log a failed LDAP bind. `reason` is a short machine-readable tag, e.g. "invalid_credentials".
pub async fn log_ldap_bind_failed(
    user_id: Option<Uuid>,
    dn: &str,
    ip: &str,
    mode: &str,
    reason: &str,
    conn: &mut SqliteConnection,
) -> Result<(), AppError> {
    let mut entry = AuditLogEntry::new(AuditEventType::LdapBindFailed)
        .ip(ip)
        .details(json!({ "dn": dn, "mode": mode, "reason": reason }));
    if let Some(uid) = user_id {
        entry = entry.user(uid);
    }
    entry.save(conn).await
}

/// Log an LDAP bind rejected because the user has TOTP enabled and the active mode cannot
/// accept an MFA-second-factor over simple bind.
pub async fn log_ldap_bind_rejected_mfa_required(
    user_id: Uuid,
    dn: &str,
    ip: &str,
    mode: &str,
    conn: &mut SqliteConnection,
) -> Result<(), AppError> {
    AuditLogEntry::new(AuditEventType::LdapBindRejectedMfaRequired)
        .user(user_id)
        .ip(ip)
        .details(json!({ "dn": dn, "mode": mode }))
        .save(conn)
        .await
}

/// Log an admin rotating the LDAP service-account bind password.
pub async fn log_ldap_bind_password_rotated(
    actor_id: Uuid,
    ctx: &AuditContext,
    conn: &mut SqliteConnection,
) -> Result<(), AppError> {
    AuditLogEntry::new(AuditEventType::LdapBindPasswordRotated)
        .actor(actor_id)
        .ip(&ctx.ip_address)
        .save(conn)
        .await
}

// ============================================================================
// SCIM helpers
// ============================================================================

fn scim_details(token_id: Uuid, token_name: &str, extra: Option<serde_json::Value>) -> serde_json::Value {
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

/// Log an admin minting a new SCIM token. Records the token label so a destructive audit
/// trail ties a specific integration ("Okta prod") to downstream user mutations.
pub async fn log_scim_token_created(
    token_id: Uuid,
    token_name: &str,
    actor_id: Uuid,
    ctx: &AuditContext,
    conn: &mut SqliteConnection,
) -> Result<(), AppError> {
    AuditLogEntry::new(AuditEventType::ScimTokenCreated)
        .actor(actor_id)
        .ip(&ctx.ip_address)
        .details(json!({ "scim_token_id": token_id, "scim_token_name": token_name }))
        .save(conn)
        .await
}

pub async fn log_scim_token_revoked(
    token_id: Uuid,
    token_name: &str,
    actor_id: Uuid,
    ctx: &AuditContext,
    conn: &mut SqliteConnection,
) -> Result<(), AppError> {
    AuditLogEntry::new(AuditEventType::ScimTokenRevoked)
        .actor(actor_id)
        .ip(&ctx.ip_address)
        .details(json!({ "scim_token_id": token_id, "scim_token_name": token_name }))
        .save(conn)
        .await
}

pub async fn log_scim_user_created(
    user_id: Uuid,
    token_id: Uuid,
    token_name: &str,
    ctx: &AuditContext,
    conn: &mut SqliteConnection,
) -> Result<(), AppError> {
    AuditLogEntry::new(AuditEventType::ScimUserCreated)
        .user(user_id)
        .ip(&ctx.ip_address)
        .details(scim_details(token_id, token_name, None))
        .save(conn)
        .await
}

pub async fn log_scim_user_updated(
    user_id: Uuid,
    token_id: Uuid,
    token_name: &str,
    changes: Option<serde_json::Value>,
    ctx: &AuditContext,
    conn: &mut SqliteConnection,
) -> Result<(), AppError> {
    AuditLogEntry::new(AuditEventType::ScimUserUpdated)
        .user(user_id)
        .ip(&ctx.ip_address)
        .details(scim_details(token_id, token_name, changes))
        .save(conn)
        .await
}

pub async fn log_scim_user_deactivated(
    user_id: Uuid,
    token_id: Uuid,
    token_name: &str,
    ctx: &AuditContext,
    conn: &mut SqliteConnection,
) -> Result<(), AppError> {
    AuditLogEntry::new(AuditEventType::ScimUserDeactivated)
        .user(user_id)
        .ip(&ctx.ip_address)
        .details(scim_details(token_id, token_name, None))
        .save(conn)
        .await
}

pub async fn log_scim_user_reactivated(
    user_id: Uuid,
    token_id: Uuid,
    token_name: &str,
    ctx: &AuditContext,
    conn: &mut SqliteConnection,
) -> Result<(), AppError> {
    AuditLogEntry::new(AuditEventType::ScimUserReactivated)
        .user(user_id)
        .ip(&ctx.ip_address)
        .details(scim_details(token_id, token_name, None))
        .save(conn)
        .await
}

pub async fn log_scim_user_deleted(
    user_id: Uuid,
    token_id: Uuid,
    token_name: &str,
    ctx: &AuditContext,
    conn: &mut SqliteConnection,
) -> Result<(), AppError> {
    AuditLogEntry::new(AuditEventType::ScimUserDeleted)
        .user(user_id)
        .ip(&ctx.ip_address)
        .details(scim_details(token_id, token_name, None))
        .save(conn)
        .await
}

/// Log admin updating system settings
pub async fn log_settings_updated(
    actor_id: Uuid,
    changes: serde_json::Value,
    ctx: &AuditContext,
    conn: &mut SqliteConnection,
) -> Result<(), AppError> {
    AuditLogEntry::new(AuditEventType::SettingsUpdated)
        .actor(actor_id)
        .ip(&ctx.ip_address)
        .details(changes)
        .save(conn)
        .await
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
        assert_eq!(AuditEventType::RoleAssigned.as_str(), "role_assigned");
        assert_eq!(AuditEventType::AdminPasswordReset.as_str(), "admin_password_reset");
        assert_eq!(AuditEventType::AdminRoleAssigned.as_str(), "admin_role_assigned");
        assert_eq!(AuditEventType::AdminRoleRemoved.as_str(), "admin_role_removed");
        assert_eq!(AuditEventType::AdminUpdateUser.as_str(), "admin_update_user");
    }

    #[test]
    fn test_audit_log_entry_builder() {
        let user_id = Uuid::now_v7();
        let actor_id = Uuid::now_v7();

        let entry = AuditLogEntry::new(AuditEventType::AdminRoleAssigned)
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
    fn test_all_event_types_have_str() {
        let all_types = [
            (AuditEventType::LoginSuccess, "login_success"),
            (AuditEventType::LoginFailed, "login_failed"),
            (AuditEventType::Logout, "logout"),
            (AuditEventType::TokenRefresh, "token_refresh"),
            (AuditEventType::UserCreated, "user_created"),
            (AuditEventType::UserUpdated, "user_updated"),
            (AuditEventType::UserDeleted, "user_deleted"),
            (AuditEventType::PasswordChanged, "password_changed"),
            (AuditEventType::RoleAssigned, "role_assigned"),
            (AuditEventType::RoleRemoved, "role_removed"),
            (AuditEventType::MfaEnabled, "mfa_enabled"),
            (AuditEventType::MfaDisabled, "mfa_disabled"),
            (AuditEventType::AdminCreateUser, "admin_create_user"),
            (AuditEventType::AdminUpdateUser, "admin_update_user"),
            (AuditEventType::AdminDeleteUser, "admin_delete_user"),
            (AuditEventType::AdminPasswordReset, "admin_password_reset"),
            (AuditEventType::AdminRoleAssigned, "admin_role_assigned"),
            (AuditEventType::AdminRoleRemoved, "admin_role_removed"),
            (AuditEventType::UserRegistered, "user_registered"),
            (AuditEventType::InvitationCreated, "invitation_created"),
            (AuditEventType::InvitationDeleted, "invitation_deleted"),
            (AuditEventType::InvitationConsumed, "invitation_consumed"),
            (AuditEventType::SettingsUpdated, "settings_updated"),
            (AuditEventType::ScimTokenCreated, "scim_token_created"),
            (AuditEventType::ScimTokenRevoked, "scim_token_revoked"),
            (AuditEventType::ScimUserCreated, "scim_user_created"),
            (AuditEventType::ScimUserUpdated, "scim_user_updated"),
            (AuditEventType::ScimUserDeactivated, "scim_user_deactivated"),
            (AuditEventType::ScimUserReactivated, "scim_user_reactivated"),
            (AuditEventType::ScimUserDeleted, "scim_user_deleted"),
        ];

        for (event_type, expected_str) in all_types {
            assert_eq!(event_type.as_str(), expected_str);
        }
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
        let entry = AuditLogEntry::new(AuditEventType::Logout);
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
        let entry = AuditLogEntry::new(AuditEventType::LoginSuccess)
            .user(uid)
            .ip("10.0.0.1");

        assert_eq!(entry.user_id, Some(uid));
        assert_eq!(entry.ip_address, Some("10.0.0.1".to_string()));
        assert!(entry.actor_id.is_none());
    }

    #[test]
    fn test_audit_log_query_builder() {
        let uid = Uuid::now_v7();
        let query = AuditLogQuery::new()
            .for_user(uid)
            .since(1000)
            .until(2000)
            .limit(50)
            .offset(10);

        assert_eq!(query.user_id, Some(uid));
        assert_eq!(query.since, Some(1000));
        assert_eq!(query.until, Some(2000));
        assert_eq!(query.limit, Some(50));
        assert_eq!(query.offset, Some(10));
    }

    #[test]
    fn test_audit_log_query_defaults() {
        let query = AuditLogQuery::new();
        assert!(query.user_id.is_none());
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
        let types = query.event_types.unwrap();
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
            ip_address: "127.0.0.1".into(),
            user_agent: None,
        };
        assert_eq!(ctx.ip_address, "127.0.0.1");
        assert!(ctx.user_agent.is_none());
    }
}

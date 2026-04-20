use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::SqliteConnection;
use uuid::Uuid;

use crate::errors::AppError;

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

    pub async fn execute(self, conn: &mut SqliteConnection) -> Result<Vec<AuditLogRecord>, AppError> {
        let mut query = String::from(
            "SELECT al.id, al.timestamp, al.event_type, al.user_id, al.actor_id, al.ip_address, al.user_agent, al.details, \
             u.username as username, actor.username as actor_username \
             FROM audit_log al \
             LEFT JOIN users u ON al.user_id = u.id \
             LEFT JOIN users actor ON al.actor_id = actor.id \
             WHERE 1=1"
        );

        if self.user_id.is_some() {
            query.push_str(" AND al.user_id = ?");
        }
        if self.since.is_some() {
            query.push_str(" AND al.timestamp >= ?");
        }
        if self.until.is_some() {
            query.push_str(" AND al.timestamp <= ?");
        }

        query.push_str(" ORDER BY al.timestamp DESC");

        if let Some(limit) = self.limit {
            query.push_str(&format!(" LIMIT {}", limit));
        }

        let records: Vec<AuditLogRecord> = sqlx::query_as(&query)
            .fetch_all(conn)
            .await?;

        Ok(records)
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

/// Paginated audit log listing for the admin UI
pub async fn list_audit_log(
    limit: i64,
    offset: i64,
    conn: &mut SqliteConnection,
) -> Result<Vec<AuditLogRecord>, AppError> {
    let records: Vec<AuditLogRecord> = sqlx::query_as(
        "SELECT al.id, al.timestamp, al.event_type, al.user_id, al.actor_id, al.ip_address, al.user_agent, al.details, \
         u.username as username, actor.username as actor_username \
         FROM audit_log al \
         LEFT JOIN users u ON al.user_id = u.id \
         LEFT JOIN users actor ON al.actor_id = actor.id \
         ORDER BY al.timestamp DESC \
         LIMIT ? OFFSET ?",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(conn)
    .await?;
    Ok(records)
}

/// Convenience function to log a login success
pub async fn log_login_success(
    user_id: Uuid,
    ip: impl Into<String>,
    user_agent: Option<String>,
    conn: &mut SqliteConnection,
) -> Result<(), AppError> {
    let mut entry = AuditLogEntry::new(AuditEventType::LoginSuccess)
        .user(user_id)
        .ip(ip);

    if let Some(ua) = user_agent {
        entry = entry.user_agent(ua);
    }

    entry.save(conn).await
}

/// Convenience function to log a login failure.
/// Pass user_id if the user account exists (wrong password); leave None for unknown usernames.
pub async fn log_login_failed(
    username: &str,
    user_id: Option<Uuid>,
    ip: impl Into<String>,
    user_agent: Option<String>,
    conn: &mut SqliteConnection,
) -> Result<(), AppError> {
    let details = if user_id.is_some() {
        json!({ "username": username })
    } else {
        json!({ "username": username, "user_exists": false })
    };

    let mut entry = AuditLogEntry::new(AuditEventType::LoginFailed)
        .ip(ip)
        .details(details);

    if let Some(uid) = user_id {
        entry = entry.user(uid);
    }

    if let Some(ua) = user_agent {
        entry = entry.user_agent(ua);
    }

    entry.save(conn).await
}

/// Convenience function to log a logout
pub async fn log_logout(
    user_id: Uuid,
    ip: impl Into<String>,
    conn: &mut SqliteConnection,
) -> Result<(), AppError> {
    AuditLogEntry::new(AuditEventType::Logout)
        .user(user_id)
        .ip(ip)
        .save(conn)
        .await
}

/// Convenience function to log a token refresh
pub async fn log_token_refresh(
    user_id: Uuid,
    ip: impl Into<String>,
    conn: &mut SqliteConnection,
) -> Result<(), AppError> {
    AuditLogEntry::new(AuditEventType::TokenRefresh)
        .user(user_id)
        .ip(ip)
        .save(conn)
        .await
}

/// Convenience function to log user creation (self-registration)
pub async fn log_user_created(
    user_id: Uuid,
    actor_id: Option<Uuid>,
    ip: impl Into<String>,
    conn: &mut SqliteConnection,
) -> Result<(), AppError> {
    let mut entry = AuditLogEntry::new(AuditEventType::UserCreated)
        .user(user_id)
        .ip(ip);

    if let Some(actor) = actor_id {
        entry = entry.actor(actor);
    }

    entry.save(conn).await
}

/// Convenience function to log a self-service password change or admin password reset
pub async fn log_password_changed(
    user_id: Uuid,
    actor_id: Option<Uuid>,
    ip: impl Into<String>,
    conn: &mut SqliteConnection,
) -> Result<(), AppError> {
    let event_type = if actor_id.is_some() {
        AuditEventType::AdminPasswordReset
    } else {
        AuditEventType::PasswordChanged
    };

    let mut entry = AuditLogEntry::new(event_type)
        .user(user_id)
        .ip(ip);

    if let Some(actor) = actor_id {
        entry = entry.actor(actor);
    }

    entry.save(conn).await
}

/// Log an admin updating a user's profile
pub async fn log_admin_update_user(
    user_id: Uuid,
    actor_id: Uuid,
    ip: impl Into<String>,
    conn: &mut SqliteConnection,
) -> Result<(), AppError> {
    AuditLogEntry::new(AuditEventType::AdminUpdateUser)
        .user(user_id)
        .actor(actor_id)
        .ip(ip)
        .save(conn)
        .await
}

/// Log an admin assigning a role to a user
pub async fn log_admin_role_assigned(
    user_id: Uuid,
    actor_id: Uuid,
    role_id: Uuid,
    role_name: &str,
    ip: impl Into<String>,
    conn: &mut SqliteConnection,
) -> Result<(), AppError> {
    AuditLogEntry::new(AuditEventType::AdminRoleAssigned)
        .user(user_id)
        .actor(actor_id)
        .ip(ip)
        .details(json!({ "role_id": role_id, "role_name": role_name }))
        .save(conn)
        .await
}

/// Log an admin removing a role from a user
pub async fn log_admin_role_removed(
    user_id: Uuid,
    actor_id: Uuid,
    role_id: Uuid,
    ip: impl Into<String>,
    conn: &mut SqliteConnection,
) -> Result<(), AppError> {
    AuditLogEntry::new(AuditEventType::AdminRoleRemoved)
        .user(user_id)
        .actor(actor_id)
        .ip(ip)
        .details(json!({ "role_id": role_id }))
        .save(conn)
        .await
}

/// Log a user self-registration
pub async fn log_user_registered(
    user_id: Uuid,
    invite_id: Option<&str>,
    ip: impl Into<String>,
    conn: &mut SqliteConnection,
) -> Result<(), AppError> {
    let details = if let Some(id) = invite_id {
        json!({ "invite_used": true, "invite_id": id })
    } else {
        json!({ "invite_used": false })
    };
    AuditLogEntry::new(AuditEventType::UserRegistered)
        .user(user_id)
        .ip(ip)
        .details(details)
        .save(conn)
        .await
}

/// Log an admin creating an invitation
pub async fn log_invitation_created(
    actor_id: Uuid,
    invite_id: &str,
    label: Option<&str>,
    ip: impl Into<String>,
    conn: &mut SqliteConnection,
) -> Result<(), AppError> {
    AuditLogEntry::new(AuditEventType::InvitationCreated)
        .actor(actor_id)
        .ip(ip)
        .details(json!({ "invite_id": invite_id, "label": label }))
        .save(conn)
        .await
}

/// Log an admin deleting an invitation
pub async fn log_invitation_deleted(
    actor_id: Uuid,
    invite_id: &str,
    ip: impl Into<String>,
    conn: &mut SqliteConnection,
) -> Result<(), AppError> {
    AuditLogEntry::new(AuditEventType::InvitationDeleted)
        .actor(actor_id)
        .ip(ip)
        .details(json!({ "invite_id": invite_id }))
        .save(conn)
        .await
}

/// Log an invitation being consumed during registration
pub async fn log_invitation_consumed(
    user_id: Uuid,
    invite_id: &str,
    ip: impl Into<String>,
    conn: &mut SqliteConnection,
) -> Result<(), AppError> {
    AuditLogEntry::new(AuditEventType::InvitationConsumed)
        .user(user_id)
        .ip(ip)
        .details(json!({ "invite_id": invite_id }))
        .save(conn)
        .await
}

/// Log admin updating system settings
pub async fn log_settings_updated(
    actor_id: Uuid,
    changes: serde_json::Value,
    ip: impl Into<String>,
    conn: &mut SqliteConnection,
) -> Result<(), AppError> {
    AuditLogEntry::new(AuditEventType::SettingsUpdated)
        .actor(actor_id)
        .ip(ip)
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
}

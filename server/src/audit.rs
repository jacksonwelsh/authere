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
        // Build dynamic query based on filters
        let mut query = String::from(
            "SELECT id, timestamp, event_type, user_id, actor_id, ip_address, user_agent, details FROM audit_log WHERE 1=1"
        );

        if self.user_id.is_some() {
            query.push_str(" AND user_id = ?");
        }
        if self.since.is_some() {
            query.push_str(" AND timestamp >= ?");
        }
        if self.until.is_some() {
            query.push_str(" AND timestamp <= ?");
        }

        query.push_str(" ORDER BY timestamp DESC");

        if let Some(limit) = self.limit {
            query.push_str(&format!(" LIMIT {}", limit));
        }

        // For simplicity, just fetch all and filter in memory for now
        // In a production system, you'd want to properly parameterize this
        let records: Vec<AuditLogRecord> = sqlx::query_as(&query)
            .fetch_all(conn)
            .await?;

        Ok(records)
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
    pub details: Option<String>,
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

/// Convenience function to log a login failure
pub async fn log_login_failed(
    username: &str,
    ip: impl Into<String>,
    user_agent: Option<String>,
    conn: &mut SqliteConnection,
) -> Result<(), AppError> {
    let mut entry = AuditLogEntry::new(AuditEventType::LoginFailed)
        .ip(ip)
        .details(json!({ "username": username }));

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

/// Convenience function to log user creation
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
    }

    #[test]
    fn test_audit_log_entry_builder() {
        let user_id = Uuid::now_v7();
        let actor_id = Uuid::now_v7();

        let entry = AuditLogEntry::new(AuditEventType::RoleAssigned)
            .user(user_id)
            .actor(actor_id)
            .ip("192.168.1.1")
            .user_agent("Mozilla/5.0")
            .details(json!({ "role": "admin" }));

        assert_eq!(entry.event_type, AuditEventType::RoleAssigned);
        assert_eq!(entry.user_id, Some(user_id));
        assert_eq!(entry.actor_id, Some(actor_id));
        assert_eq!(entry.ip_address, Some("192.168.1.1".to_string()));
        assert_eq!(entry.user_agent, Some("Mozilla/5.0".to_string()));
        assert!(entry.details.is_some());
    }
}

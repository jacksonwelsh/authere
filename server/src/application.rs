use regex::RegexBuilder;
use serde::{Deserialize, Serialize};
use sqlx::SqliteConnection;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::db::DbEntity;
use crate::errors::AppError;

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct Application {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub host_pattern: Option<String>,
    pub path_prefix: Option<String>,
    pub required_roles: Vec<String>,
    pub enabled: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateApplicationInput {
    pub name: String,
    pub slug: String,
    pub host_pattern: Option<String>,
    pub path_prefix: Option<String>,
    pub required_roles: Option<Vec<String>>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateApplicationInput {
    pub name: Option<String>,
    pub host_pattern: Option<String>,
    pub path_prefix: Option<String>,
    pub required_roles: Option<Vec<String>>,
    pub enabled: Option<bool>,
}

/// Internal struct for database row mapping
#[derive(Debug, sqlx::FromRow)]
struct ApplicationRow {
    id: Uuid,
    name: String,
    slug: String,
    host_pattern: Option<String>,
    path_prefix: Option<String>,
    required_roles: Option<String>,
    enabled: i64,
    created_at: i64,
    updated_at: i64,
}

impl From<ApplicationRow> for Application {
    fn from(row: ApplicationRow) -> Self {
        let required_roles: Vec<String> = row
            .required_roles
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();

        Application {
            id: row.id,
            name: row.name,
            slug: row.slug,
            host_pattern: row.host_pattern,
            path_prefix: row.path_prefix,
            required_roles,
            enabled: row.enabled != 0,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

fn current_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as i64
}

impl Application {
    pub fn new(input: CreateApplicationInput) -> Self {
        let now = current_timestamp();
        Self {
            id: Uuid::now_v7(),
            name: input.name,
            slug: input.slug,
            host_pattern: input.host_pattern,
            path_prefix: input.path_prefix,
            required_roles: input.required_roles.unwrap_or_default(),
            enabled: input.enabled.unwrap_or(true),
            created_at: now,
            updated_at: now,
        }
    }

    /// List all applications
    pub async fn list(conn: &mut SqliteConnection) -> Result<Vec<Application>, AppError> {
        let rows: Vec<ApplicationRow> = sqlx::query_as(
            r#"SELECT id, name, slug, host_pattern, path_prefix, required_roles, enabled, created_at, updated_at
               FROM applications ORDER BY name"#
        )
        .fetch_all(conn)
        .await?;

        Ok(rows.into_iter().map(Application::from).collect())
    }

    /// List only enabled applications
    pub async fn list_enabled(conn: &mut SqliteConnection) -> Result<Vec<Application>, AppError> {
        let rows: Vec<ApplicationRow> = sqlx::query_as(
            r#"SELECT id, name, slug, host_pattern, path_prefix, required_roles, enabled, created_at, updated_at
               FROM applications WHERE enabled = 1 ORDER BY name"#
        )
        .fetch_all(conn)
        .await?;

        Ok(rows.into_iter().map(Application::from).collect())
    }

    /// Get application by slug
    pub async fn get_by_slug(slug: &str, conn: &mut SqliteConnection) -> Result<Option<Application>, AppError> {
        let row: Option<ApplicationRow> = sqlx::query_as(
            r#"SELECT id, name, slug, host_pattern, path_prefix, required_roles, enabled, created_at, updated_at
               FROM applications WHERE slug = ?"#
        )
        .bind(slug)
        .fetch_optional(conn)
        .await?;

        Ok(row.map(Application::from))
    }

    /// Find application matching the given host and path
    pub async fn find_matching(
        host: &str,
        path: &str,
        conn: &mut SqliteConnection,
    ) -> Result<Option<Application>, AppError> {
        let apps = Application::list_enabled(conn).await?;

        for app in apps {
            if app.matches(host, path) {
                return Ok(Some(app));
            }
        }

        Ok(None)
    }

    /// Check if this application matches the given host and path
    pub fn matches(&self, host: &str, path: &str) -> bool {
        // Check host pattern
        if let Some(pattern) = &self.host_pattern {
            if pattern == host {
                // Exact match, check path
            } else if let Ok(re) = RegexBuilder::new(&format!("^(?:{pattern})$"))
                .size_limit(10_000)
                .build()
            {
                if !re.is_match(host) {
                    return false;
                }
            } else {
                return false;
            }
        }

        // Check path prefix
        if let Some(prefix) = &self.path_prefix {
            if !path.starts_with(prefix) {
                return false;
            }
        }

        true
    }

    /// Check if the given roles satisfy this application's requirements
    pub fn check_access(&self, user_roles: &[String]) -> bool {
        if self.required_roles.is_empty() {
            // No roles required, any authenticated user can access
            return true;
        }

        // User must have at least one of the required roles
        for required in &self.required_roles {
            if user_roles.contains(required) {
                return true;
            }
        }

        false
    }

    /// Update the application
    pub async fn update(
        &mut self,
        input: UpdateApplicationInput,
        conn: &mut SqliteConnection,
    ) -> Result<(), AppError> {
        if let Some(name) = input.name {
            self.name = name;
        }
        if let Some(host_pattern) = input.host_pattern {
            self.host_pattern = Some(host_pattern);
        }
        if let Some(path_prefix) = input.path_prefix {
            self.path_prefix = Some(path_prefix);
        }
        if let Some(required_roles) = input.required_roles {
            self.required_roles = required_roles;
        }
        if let Some(enabled) = input.enabled {
            self.enabled = enabled;
        }

        self.updated_at = current_timestamp();

        let roles_json = serde_json::to_string(&self.required_roles)
            .map_err(|e| AppError::InternalError(format!("Failed to serialize roles: {e}")))?;
        let enabled_int: i64 = if self.enabled { 1 } else { 0 };

        sqlx::query!(
            r#"UPDATE applications SET name = ?, host_pattern = ?, path_prefix = ?, required_roles = ?, enabled = ?, updated_at = ?
               WHERE id = ?"#,
            self.name,
            self.host_pattern,
            self.path_prefix,
            roles_json,
            enabled_int,
            self.updated_at,
            self.id
        )
        .execute(conn)
        .await?;

        Ok(())
    }

    /// Delete the application
    pub async fn delete(id: Uuid, conn: &mut SqliteConnection) -> Result<bool, AppError> {
        let result = sqlx::query!("DELETE FROM applications WHERE id = ?", id)
            .execute(conn)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Validate application input
    pub fn validate_input(input: &CreateApplicationInput) -> Result<(), AppError> {
        let mut errors = Vec::new();

        if input.name.is_empty() || input.name.len() > 128 {
            errors.push("Application name must be between 1 and 128 characters".to_string());
        }

        if input.slug.is_empty() || input.slug.len() > 64 {
            errors.push("Slug must be between 1 and 64 characters".to_string());
        }

        if !input.slug.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
            errors.push("Slug must contain only alphanumeric characters, hyphens, and underscores".to_string());
        }

        // Validate host pattern as regex if provided
        if let Some(pattern) = &input.host_pattern {
            if RegexBuilder::new(&format!("^(?:{pattern})$")).size_limit(10_000).build().is_err() {
                errors.push("Invalid host pattern regex".to_string());
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(AppError::InputError(errors))
        }
    }
}

impl DbEntity for Application {
    async fn save(&self, conn: &mut SqliteConnection) -> Result<(), AppError> {
        let roles_json = serde_json::to_string(&self.required_roles)
            .map_err(|e| AppError::InternalError(format!("Failed to serialize roles: {e}")))?;
        let enabled_int: i64 = if self.enabled { 1 } else { 0 };

        sqlx::query!(
            r#"INSERT INTO applications (id, name, slug, host_pattern, path_prefix, required_roles, enabled, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
            self.id,
            self.name,
            self.slug,
            self.host_pattern,
            self.path_prefix,
            roles_json,
            enabled_int,
            self.created_at,
            self.updated_at
        )
        .execute(conn)
        .await?;

        Ok(())
    }

    async fn get(id: Uuid, conn: &mut SqliteConnection) -> Result<Option<Self>, AppError> {
        let row: Option<ApplicationRow> = sqlx::query_as(
            r#"SELECT id, name, slug, host_pattern, path_prefix, required_roles, enabled, created_at, updated_at
               FROM applications WHERE id = ?"#
        )
        .bind(id)
        .fetch_optional(conn)
        .await?;

        Ok(row.map(Application::from))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matches_exact_host() {
        let app = Application {
            id: Uuid::now_v7(),
            name: "Test".to_string(),
            slug: "test".to_string(),
            host_pattern: Some("app.example.com".to_string()),
            path_prefix: None,
            required_roles: vec![],
            enabled: true,
            created_at: 0,
            updated_at: 0,
        };

        assert!(app.matches("app.example.com", "/"));
        assert!(!app.matches("other.example.com", "/"));
    }

    #[test]
    fn test_matches_host_regex() {
        let app = Application {
            id: Uuid::now_v7(),
            name: "Test".to_string(),
            slug: "test".to_string(),
            host_pattern: Some(r".*\.example\.com".to_string()),
            path_prefix: None,
            required_roles: vec![],
            enabled: true,
            created_at: 0,
            updated_at: 0,
        };

        assert!(app.matches("app.example.com", "/"));
        assert!(app.matches("other.example.com", "/"));
        assert!(!app.matches("example.org", "/"));
    }

    #[test]
    fn test_matches_path_prefix() {
        let app = Application {
            id: Uuid::now_v7(),
            name: "Test".to_string(),
            slug: "test".to_string(),
            host_pattern: None,
            path_prefix: Some("/api/".to_string()),
            required_roles: vec![],
            enabled: true,
            created_at: 0,
            updated_at: 0,
        };

        assert!(app.matches("any.host", "/api/users"));
        assert!(app.matches("any.host", "/api/"));
        assert!(!app.matches("any.host", "/web/"));
    }

    #[test]
    fn test_check_access_no_roles_required() {
        let app = Application {
            id: Uuid::now_v7(),
            name: "Test".to_string(),
            slug: "test".to_string(),
            host_pattern: None,
            path_prefix: None,
            required_roles: vec![],
            enabled: true,
            created_at: 0,
            updated_at: 0,
        };

        assert!(app.check_access(&[]));
        assert!(app.check_access(&["user".to_string()]));
    }

    #[test]
    fn test_check_access_with_roles() {
        let app = Application {
            id: Uuid::now_v7(),
            name: "Test".to_string(),
            slug: "test".to_string(),
            host_pattern: None,
            path_prefix: None,
            required_roles: vec!["admin".to_string(), "power_user".to_string()],
            enabled: true,
            created_at: 0,
            updated_at: 0,
        };

        assert!(!app.check_access(&[]));
        assert!(!app.check_access(&["user".to_string()]));
        assert!(app.check_access(&["admin".to_string()]));
        assert!(app.check_access(&["power_user".to_string()]));
        assert!(app.check_access(&["user".to_string(), "admin".to_string()]));
    }

    #[test]
    fn test_validate_input_valid() {
        let input = CreateApplicationInput {
            name: "My App".to_string(),
            slug: "my-app".to_string(),
            host_pattern: Some("app.example.com".to_string()),
            path_prefix: None,
            required_roles: Some(vec!["user".to_string()]),
            enabled: Some(true),
        };

        assert!(Application::validate_input(&input).is_ok());
    }

    #[test]
    fn test_validate_input_invalid_slug() {
        let input = CreateApplicationInput {
            name: "My App".to_string(),
            slug: "my app".to_string(), // spaces not allowed
            host_pattern: None,
            path_prefix: None,
            required_roles: None,
            enabled: None,
        };

        assert!(Application::validate_input(&input).is_err());
    }

    #[test]
    fn test_validate_input_invalid_regex() {
        let input = CreateApplicationInput {
            name: "My App".to_string(),
            slug: "my-app".to_string(),
            host_pattern: Some("[invalid".to_string()), // invalid regex
            path_prefix: None,
            required_roles: None,
            enabled: None,
        };

        assert!(Application::validate_input(&input).is_err());
    }
}

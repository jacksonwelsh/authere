use serde::{Deserialize, Serialize};
use sqlx::SqliteConnection;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::db::DbEntity;
use crate::errors::AppError;

pub const ROLE_ADMIN: &str = "admin";
pub const ROLE_USER: &str = "user";

#[derive(Debug, Serialize, Deserialize, ToSchema, sqlx::FromRow)]
pub struct Role {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateRoleInput {
    pub name: String,
    pub description: Option<String>,
}

impl Role {
    pub fn new(name: String, description: Option<String>) -> Self {
        Self {
            id: Uuid::now_v7(),
            name,
            description,
        }
    }

    /// List all roles
    pub async fn list(conn: &mut SqliteConnection) -> Result<Vec<Role>, AppError> {
        let roles = sqlx::query_as!(
            Role,
            r#"SELECT id as "id: Uuid", name, description FROM roles ORDER BY name"#
        )
        .fetch_all(conn)
        .await?;

        Ok(roles)
    }

    /// Get a role by name
    pub async fn get_by_name(name: &str, conn: &mut SqliteConnection) -> Result<Option<Role>, AppError> {
        let role = sqlx::query_as!(
            Role,
            r#"SELECT id as "id: Uuid", name, description FROM roles WHERE name = ?"#,
            name
        )
        .fetch_optional(conn)
        .await?;

        Ok(role)
    }

    /// Delete a role (fails if role is assigned to any users)
    pub async fn delete(id: Uuid, conn: &mut SqliteConnection) -> Result<bool, AppError> {
        // Check if any users have this role
        let user_count: i64 = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM user_roles WHERE role_id = ?",
            id
        )
        .fetch_one(&mut *conn)
        .await?;

        if user_count > 0 {
            return Err(AppError::InputError(vec![format!(
                "Cannot delete role: {} users have this role assigned",
                user_count
            )]));
        }

        // Prevent deletion of built-in roles
        let role = Role::get(id, &mut *conn).await?;
        if let Some(r) = &role {
            if r.name == ROLE_ADMIN || r.name == ROLE_USER {
                return Err(AppError::InputError(vec![
                    "Cannot delete built-in roles (admin, user)".to_string()
                ]));
            }
        }

        let result = sqlx::query!("DELETE FROM roles WHERE id = ?", id)
            .execute(conn)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Validate role input
    pub fn validate_input(input: &CreateRoleInput) -> Result<(), AppError> {
        let mut errors = Vec::new();

        if input.name.is_empty() || input.name.len() > 64 {
            errors.push("Role name must be between 1 and 64 characters".to_string());
        }

        if !input.name.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
            errors.push("Role name must contain only alphanumeric characters, underscores, and hyphens".to_string());
        }

        if let Some(desc) = &input.description {
            if desc.len() > 256 {
                errors.push("Role description must be 256 characters or less".to_string());
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(AppError::InputError(errors))
        }
    }
}

impl DbEntity for Role {
    async fn save(&self, conn: &mut SqliteConnection) -> Result<(), AppError> {
        sqlx::query!(
            "INSERT INTO roles (id, name, description) VALUES (?, ?, ?)",
            self.id,
            self.name,
            self.description
        )
        .execute(conn)
        .await?;

        Ok(())
    }

    async fn get(id: Uuid, conn: &mut SqliteConnection) -> Result<Option<Self>, AppError> {
        let role = sqlx::query_as!(
            Role,
            r#"SELECT id as "id: Uuid", name, description FROM roles WHERE id = ?"#,
            id
        )
        .fetch_optional(conn)
        .await?;

        Ok(role)
    }
}

/// Represents a user's role assignment
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct UserRole {
    pub user_id: Uuid,
    pub role_id: Uuid,
    pub role_name: String,
}

impl UserRole {
    /// Get all roles for a user
    pub async fn get_for_user(user_id: Uuid, conn: &mut SqliteConnection) -> Result<Vec<UserRole>, AppError> {
        let roles = sqlx::query_as!(
            UserRole,
            r#"SELECT ur.user_id as "user_id: Uuid", ur.role_id as "role_id: Uuid", r.name as role_name
               FROM user_roles ur
               INNER JOIN roles r ON r.id = ur.role_id
               WHERE ur.user_id = ?"#,
            user_id
        )
        .fetch_all(conn)
        .await?;

        Ok(roles)
    }

    /// Assign a role to a user
    pub async fn assign(user_id: Uuid, role_id: Uuid, conn: &mut SqliteConnection) -> Result<(), AppError> {
        // Check if already assigned
        let count: i64 = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM user_roles WHERE user_id = ? AND role_id = ?",
            user_id,
            role_id
        )
        .fetch_one(&mut *conn)
        .await?;

        if count > 0 {
            return Err(AppError::UniqueError("Role already assigned to user".to_string()));
        }

        sqlx::query!(
            "INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)",
            user_id,
            role_id
        )
        .execute(conn)
        .await?;

        Ok(())
    }

    /// Remove a role from a user
    pub async fn remove(user_id: Uuid, role_id: Uuid, conn: &mut SqliteConnection) -> Result<bool, AppError> {
        let result = sqlx::query!(
            "DELETE FROM user_roles WHERE user_id = ? AND role_id = ?",
            user_id,
            role_id
        )
        .execute(conn)
        .await?;

        Ok(result.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_role_name_empty() {
        let input = CreateRoleInput {
            name: String::new(),
            description: None,
        };
        let result = Role::validate_input(&input);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_role_name_too_long() {
        let input = CreateRoleInput {
            name: "a".repeat(65),
            description: None,
        };
        let result = Role::validate_input(&input);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_role_name_invalid_chars() {
        let input = CreateRoleInput {
            name: "admin role".to_string(), // spaces not allowed
            description: None,
        };
        let result = Role::validate_input(&input);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_role_description_too_long() {
        let input = CreateRoleInput {
            name: "valid_role".to_string(),
            description: Some("a".repeat(257)),
        };
        let result = Role::validate_input(&input);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_role_ok() {
        let input = CreateRoleInput {
            name: "power_users".to_string(),
            description: Some("Users with elevated privileges".to_string()),
        };
        let result = Role::validate_input(&input);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_role_name_with_hyphens_underscores() {
        let input = CreateRoleInput {
            name: "power-users_v2".to_string(),
            description: None,
        };
        let result = Role::validate_input(&input);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_role_name_special_chars() {
        for name in ["admin@role", "role.name", "role/name", "role name"] {
            let input = CreateRoleInput {
                name: name.to_string(),
                description: None,
            };
            assert!(
                Role::validate_input(&input).is_err(),
                "{name} should be rejected"
            );
        }
    }

    #[test]
    fn test_validate_role_max_length_name() {
        let input = CreateRoleInput {
            name: "a".repeat(64),
            description: None,
        };
        assert!(Role::validate_input(&input).is_ok());
    }

    #[test]
    fn test_validate_role_max_length_description() {
        let input = CreateRoleInput {
            name: "valid".to_string(),
            description: Some("a".repeat(256)),
        };
        assert!(Role::validate_input(&input).is_ok());
    }

    #[test]
    fn test_validate_role_multiple_errors() {
        let input = CreateRoleInput {
            name: "".to_string(),
            description: Some("a".repeat(257)),
        };
        let err = Role::validate_input(&input).unwrap_err();
        if let AppError::InputError(errs) = err {
            assert!(errs.len() >= 2);
        } else {
            panic!("Expected InputError");
        }
    }

    #[test]
    fn test_role_new() {
        let role = Role::new("editor".into(), Some("Can edit".into()));
        assert_eq!(role.name, "editor");
        assert_eq!(role.description, Some("Can edit".into()));
    }

    #[test]
    fn test_role_new_no_description() {
        let role = Role::new("viewer".into(), None);
        assert_eq!(role.name, "viewer");
        assert!(role.description.is_none());
    }

    #[test]
    fn test_role_serialization_roundtrip() {
        let role = Role::new("test-role".into(), Some("desc".into()));
        let json = serde_json::to_string(&role).unwrap();
        let deserialized: Role = serde_json::from_str(&json).unwrap();
        assert_eq!(role.id, deserialized.id);
        assert_eq!(role.name, deserialized.name);
        assert_eq!(role.description, deserialized.description);
    }
}

pub mod auth;

use crate::db::{DbEntity};
use crate::errors::AppError;

use serde::{Deserialize, Serialize};
use sqlx::SqliteConnection;
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub name: String,
    /// Manually-created users don't need an email address, but it's always nice to have one.
    pub email: Option<String>,
}

impl User {
    pub fn new(username: String, name: String, email: Option<String>) -> User {
        User {
            id: Uuid::now_v7(),
            username,
            name,
            email,
        }
    }

    pub async fn list(conn: &mut SqliteConnection) -> Result<Vec<User>, AppError> {
        Ok(sqlx::query_as!(
            User,
            r#"SELECT id as "id: uuid::Uuid", name, username, email FROM users"#
        )
        .fetch_all(conn)
        .await?)
    }
}

impl DbEntity for User {
    async fn save(&self, conn: &mut SqliteConnection) -> Result<(), AppError> {
        sqlx::query!(
            "INSERT INTO users (id, username, name, email) VALUES (?, ?, ?, ?)",
            self.id,
            self.username,
            self.name,
            self.email
        )
        .execute(conn)
        .await?;

        Ok(())
    }

    async fn get(id: uuid::Uuid, conn: &mut SqliteConnection) -> Result<Option<Self>, AppError> {
        Ok(sqlx::query_as!(
            User,
            r#"SELECT id as "id: uuid::Uuid", username, name, email FROM users WHERE id = ?"#,
            id
        )
        .fetch_optional(conn)
        .await?)
    }
}

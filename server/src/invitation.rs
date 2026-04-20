use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sqlx::SqliteConnection;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::errors::AppError;

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct Invitation {
    pub id: String,
    pub created_by: Uuid,
    pub label: Option<String>,
    pub max_uses: Option<i64>,
    pub uses: i64,
    pub expires_at: Option<i64>,
    pub created_at: i64,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct InvitationWithStatus {
    pub id: String,
    pub created_by: Uuid,
    pub created_by_username: Option<String>,
    pub label: Option<String>,
    pub max_uses: Option<i64>,
    pub uses: i64,
    pub expires_at: Option<i64>,
    pub created_at: i64,
    pub status: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateInvitationInput {
    pub label: Option<String>,
    pub max_uses: Option<i64>,
    pub expires_at: Option<i64>,
}

fn current_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as i64
}

fn generate_id() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

impl Invitation {
    pub fn new(input: CreateInvitationInput, created_by: Uuid) -> Self {
        Self {
            id: generate_id(),
            created_by,
            label: input.label,
            max_uses: input.max_uses,
            uses: 0,
            expires_at: input.expires_at,
            created_at: current_timestamp(),
        }
    }

    pub fn is_valid(&self) -> bool {
        let now = current_timestamp();
        let not_expired = self.expires_at.map_or(true, |exp| exp > now);
        let not_exhausted = self.max_uses.map_or(true, |max| self.uses < max);
        not_expired && not_exhausted
    }

    pub async fn save(&self, conn: &mut SqliteConnection) -> Result<(), AppError> {
        sqlx::query!(
            "INSERT INTO invitations (id, created_by, label, max_uses, uses, expires_at, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
            self.id,
            self.created_by,
            self.label,
            self.max_uses,
            self.uses,
            self.expires_at,
            self.created_at
        )
        .execute(conn)
        .await?;
        Ok(())
    }

    pub async fn list(conn: &mut SqliteConnection) -> Result<Vec<InvitationWithStatus>, AppError> {
        let rows = sqlx::query!(
            r#"SELECT i.id, i.created_by as "created_by: Uuid", i.label, i.max_uses, i.uses,
                      i.expires_at, i.created_at, u.username as created_by_username
               FROM invitations i
               LEFT JOIN users u ON i.created_by = u.id
               ORDER BY i.created_at DESC"#
        )
        .fetch_all(conn)
        .await?;

        let now = current_timestamp();
        let invitations = rows
            .into_iter()
            .map(|r| {
                let not_expired = r.expires_at.map_or(true, |exp| exp > now);
                let not_exhausted = r.max_uses.map_or(true, |max| r.uses < max);
                let status = if !not_expired {
                    "expired"
                } else if !not_exhausted {
                    "exhausted"
                } else {
                    "active"
                }
                .to_string();

                InvitationWithStatus {
                    id: r.id,
                    created_by: r.created_by,
                    created_by_username: r.created_by_username,
                    label: r.label,
                    max_uses: r.max_uses,
                    uses: r.uses,
                    expires_at: r.expires_at,
                    created_at: r.created_at,
                    status,
                }
            })
            .collect();

        Ok(invitations)
    }

    pub async fn get(id: &str, conn: &mut SqliteConnection) -> Result<Option<Self>, AppError> {
        let row = sqlx::query!(
            r#"SELECT id, created_by as "created_by: Uuid", label, max_uses, uses, expires_at, created_at
               FROM invitations WHERE id = ?"#,
            id
        )
        .fetch_optional(conn)
        .await?;

        Ok(row.map(|r| Invitation {
            id: r.id,
            created_by: r.created_by,
            label: r.label,
            max_uses: r.max_uses,
            uses: r.uses,
            expires_at: r.expires_at,
            created_at: r.created_at,
        }))
    }

    pub async fn delete(id: &str, conn: &mut SqliteConnection) -> Result<bool, AppError> {
        let result = sqlx::query!("DELETE FROM invitations WHERE id = ?", id)
            .execute(conn)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Atomically consume one use of the invitation. Returns None if the invitation
    /// is invalid, exhausted, or expired.
    pub async fn consume(id: &str, conn: &mut SqliteConnection) -> Result<Option<Self>, AppError> {
        let row = sqlx::query!(
            r#"UPDATE invitations
               SET uses = uses + 1
               WHERE id = ?
                 AND (max_uses IS NULL OR uses < max_uses)
                 AND (expires_at IS NULL OR expires_at > unixepoch())
               RETURNING id, created_by as "created_by: Uuid", label, max_uses, uses, expires_at, created_at"#,
            id
        )
        .fetch_optional(conn)
        .await?;

        Ok(row.map(|r| Invitation {
            id: r.id,
            created_by: r.created_by,
            label: r.label,
            max_uses: r.max_uses,
            uses: r.uses,
            expires_at: r.expires_at,
            created_at: r.created_at,
        }))
    }

    pub fn validate_input(input: &CreateInvitationInput) -> Result<(), AppError> {
        let mut errors = Vec::new();

        if let Some(max_uses) = input.max_uses {
            if max_uses < 1 {
                errors.push("max_uses must be at least 1".to_string());
            }
        }

        if let Some(expires_at) = input.expires_at {
            if expires_at <= current_timestamp() {
                errors.push("expires_at must be in the future".to_string());
            }
        }

        if let Some(label) = &input.label {
            if label.len() > 128 {
                errors.push("label must be 128 characters or fewer".to_string());
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(AppError::InputError(errors))
        }
    }
}

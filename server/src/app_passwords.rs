use std::time::{SystemTime, UNIX_EPOCH};

use argon2::{
    Argon2, PasswordHash, PasswordVerifier,
    password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sqlx::SqliteConnection;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::errors::AppError;

const MIN_NAME_LEN: usize = 1;
const MAX_NAME_LEN: usize = 64;
const PASSWORD_LEN: usize = 24;

const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";

/// App-password metadata, safe to serialise over the API. The hash never leaves the database.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, sqlx::FromRow)]
pub struct AppPassword {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreateAppPasswordInput {
    pub name: String,
}

/// Response on creation, including the *only* time the cleartext password is exposed.
#[derive(Debug, Serialize, ToSchema)]
pub struct CreateAppPasswordResponse {
    pub app_password: AppPassword,
    pub password: String,
}

impl AppPassword {
    pub fn validate_name(name: &str) -> Result<(), String> {
        let trimmed = name.trim();
        if trimmed.len() < MIN_NAME_LEN {
            Err("Name cannot be empty".to_string())
        } else if trimmed.len() > MAX_NAME_LEN {
            Err(format!("Name must be {MAX_NAME_LEN} characters or fewer"))
        } else {
            Ok(())
        }
    }

    /// Create a new app password for the given user. The cleartext password is generated on
    /// the server and returned; only the Argon2 hash is stored.
    pub async fn create(
        user_id: Uuid,
        name: &str,
        conn: &mut SqliteConnection,
    ) -> Result<(Self, String), AppError> {
        Self::validate_name(name).map_err(|e| AppError::InputError(vec![e]))?;

        let cleartext = generate_password();
        let hash = Argon2::default()
            .hash_password(cleartext.as_bytes(), &SaltString::generate(&mut OsRng))
            .map_err(|e| AppError::InternalError(format!("Failed to hash password: {e}")))?
            .to_string();

        let now = now_unix();
        let record = AppPassword {
            id: Uuid::now_v7(),
            user_id,
            name: name.trim().to_string(),
            created_at: now,
            last_used_at: None,
        };

        sqlx::query!(
            "INSERT INTO app_passwords (id, user_id, name, password_hash, created_at, last_used_at)
             VALUES (?, ?, ?, ?, ?, NULL)",
            record.id,
            record.user_id,
            record.name,
            hash,
            record.created_at
        )
        .execute(conn)
        .await?;

        Ok((record, cleartext))
    }

    pub async fn list_for_user(
        user_id: Uuid,
        conn: &mut SqliteConnection,
    ) -> Result<Vec<Self>, AppError> {
        let rows = sqlx::query_as!(
            AppPassword,
            r#"SELECT id as "id: Uuid", user_id as "user_id: Uuid", name, created_at, last_used_at
               FROM app_passwords WHERE user_id = ? ORDER BY created_at DESC"#,
            user_id
        )
        .fetch_all(conn)
        .await?;
        Ok(rows)
    }

    /// Delete an app password belonging to `user_id`. Returns true if a row was removed.
    pub async fn delete_for_user(
        id: Uuid,
        user_id: Uuid,
        conn: &mut SqliteConnection,
    ) -> Result<bool, AppError> {
        let res = sqlx::query!(
            "DELETE FROM app_passwords WHERE id = ? AND user_id = ?",
            id,
            user_id
        )
        .execute(conn)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Try to verify a cleartext password against every app password for the given user.
    /// On match, updates `last_used_at`. Returns the matching row's id so the caller can
    /// audit/trace which password was used.
    pub async fn verify_for_user(
        user_id: Uuid,
        cleartext: &str,
        conn: &mut SqliteConnection,
    ) -> Result<Option<Uuid>, AppError> {
        let rows = sqlx::query!(
            r#"SELECT id as "id: Uuid", password_hash FROM app_passwords WHERE user_id = ?"#,
            user_id
        )
        .fetch_all(&mut *conn)
        .await?;

        for row in rows {
            let Ok(parsed) = PasswordHash::new(&row.password_hash) else {
                continue;
            };
            if Argon2::default()
                .verify_password(cleartext.as_bytes(), &parsed)
                .is_ok()
            {
                let now = now_unix();
                let _ = sqlx::query!(
                    "UPDATE app_passwords SET last_used_at = ? WHERE id = ?",
                    now,
                    row.id
                )
                .execute(&mut *conn)
                .await;
                return Ok(Some(row.id));
            }
        }
        Ok(None)
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn generate_password() -> String {
    let mut rng = rand::thread_rng();
    (0..PASSWORD_LEN)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::SqlitePool;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn in_memory_pool() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .connect("sqlite::memory:")
            .await
            .expect("connect sqlite in-memory");
        sqlx::migrate!("../migrations")
            .run(&pool)
            .await
            .expect("run migrations");
        pool
    }

    async fn insert_user(pool: &SqlitePool) -> Uuid {
        let id = Uuid::now_v7();
        sqlx::query!(
            "INSERT INTO users (id, username, name, email) VALUES (?, ?, ?, NULL)",
            id,
            "alice",
            "Alice"
        )
        .execute(pool)
        .await
        .expect("insert user");
        id
    }

    #[test]
    fn validate_name_accepts_reasonable_names() {
        AppPassword::validate_name("Jellyfin").unwrap();
        AppPassword::validate_name("x").unwrap();
        AppPassword::validate_name(&"a".repeat(MAX_NAME_LEN)).unwrap();
    }

    #[test]
    fn validate_name_rejects_empty_or_too_long() {
        assert!(AppPassword::validate_name("").is_err());
        assert!(AppPassword::validate_name("   ").is_err());
        assert!(AppPassword::validate_name(&"a".repeat(MAX_NAME_LEN + 1)).is_err());
    }

    #[test]
    fn generate_password_has_correct_length_and_charset() {
        for _ in 0..20 {
            let pw = generate_password();
            assert_eq!(pw.len(), PASSWORD_LEN);
            assert!(pw.chars().all(|c| CHARSET.contains(&(c as u8))));
        }
    }

    #[test]
    fn generate_password_is_not_deterministic() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..50 {
            seen.insert(generate_password());
        }
        assert!(seen.len() > 40, "passwords should be highly unique");
    }

    #[tokio::test]
    async fn create_list_delete_roundtrip() {
        let pool = in_memory_pool().await;
        let user_id = insert_user(&pool).await;

        let mut conn = pool.acquire().await.unwrap();
        let (record, cleartext) = AppPassword::create(user_id, "Jellyfin", &mut conn).await.unwrap();
        assert_eq!(cleartext.len(), PASSWORD_LEN);
        assert_eq!(record.name, "Jellyfin");

        let listed = AppPassword::list_for_user(user_id, &mut conn).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, record.id);

        let deleted = AppPassword::delete_for_user(record.id, user_id, &mut conn).await.unwrap();
        assert!(deleted);
        let listed = AppPassword::list_for_user(user_id, &mut conn).await.unwrap();
        assert!(listed.is_empty());
    }

    #[tokio::test]
    async fn verify_matches_correct_password_only() {
        let pool = in_memory_pool().await;
        let user_id = insert_user(&pool).await;

        let mut conn = pool.acquire().await.unwrap();
        let (record, cleartext) = AppPassword::create(user_id, "Jellyfin", &mut conn).await.unwrap();

        let matched = AppPassword::verify_for_user(user_id, &cleartext, &mut conn)
            .await
            .unwrap();
        assert_eq!(matched, Some(record.id));

        let not_matched = AppPassword::verify_for_user(user_id, "wrong-password", &mut conn)
            .await
            .unwrap();
        assert_eq!(not_matched, None);
    }

    #[tokio::test]
    async fn verify_picks_correct_entry_when_user_has_multiple() {
        let pool = in_memory_pool().await;
        let user_id = insert_user(&pool).await;

        let mut conn = pool.acquire().await.unwrap();
        let (_a, pw_a) = AppPassword::create(user_id, "Jellyfin", &mut conn).await.unwrap();
        let (b, pw_b) = AppPassword::create(user_id, "Sonarr", &mut conn).await.unwrap();

        let matched = AppPassword::verify_for_user(user_id, &pw_b, &mut conn)
            .await
            .unwrap();
        assert_eq!(matched, Some(b.id));

        // Sanity: the other one also still verifies
        let matched_a = AppPassword::verify_for_user(user_id, &pw_a, &mut conn)
            .await
            .unwrap();
        assert!(matched_a.is_some());
    }

    #[tokio::test]
    async fn verify_updates_last_used_at() {
        let pool = in_memory_pool().await;
        let user_id = insert_user(&pool).await;

        let mut conn = pool.acquire().await.unwrap();
        let (record, cleartext) = AppPassword::create(user_id, "Jellyfin", &mut conn).await.unwrap();
        assert!(record.last_used_at.is_none());

        AppPassword::verify_for_user(user_id, &cleartext, &mut conn)
            .await
            .unwrap();

        let listed = AppPassword::list_for_user(user_id, &mut conn).await.unwrap();
        assert!(listed[0].last_used_at.is_some());
    }

    #[tokio::test]
    async fn delete_is_scoped_to_user() {
        let pool = in_memory_pool().await;
        let user_a = insert_user(&pool).await;

        let user_b = {
            let id = Uuid::now_v7();
            sqlx::query!(
                "INSERT INTO users (id, username, name, email) VALUES (?, ?, ?, NULL)",
                id, "bob", "Bob"
            )
            .execute(&pool)
            .await
            .unwrap();
            id
        };

        let mut conn = pool.acquire().await.unwrap();
        let (record, _) = AppPassword::create(user_a, "A", &mut conn).await.unwrap();

        // B should not be able to delete A's entry.
        let deleted = AppPassword::delete_for_user(record.id, user_b, &mut conn).await.unwrap();
        assert!(!deleted);
        assert_eq!(
            AppPassword::list_for_user(user_a, &mut conn).await.unwrap().len(),
            1
        );
    }
}

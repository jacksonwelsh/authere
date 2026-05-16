pub mod auth;

use std::sync::LazyLock;

use crate::errors::AppError;
use crate::{db::DbEntity, user::auth::Authenticator};

use regex::Regex;
use serde::{Deserialize, Serialize};
use sqlx::SqliteConnection;
use utoipa::ToSchema;
use uuid::Uuid;

const USERNAME_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9.\-_]*$").expect("invalid username regex"));
const MIN_USERNAME_LEN: usize = 3;
const MAX_USERNAME_LEN: usize = 64;

const MIN_NAME_LEN: usize = 3;
const MAX_NAME_LEN: usize = 128;

/// Specified by RFC 3936 errata
const MAX_EMAIL_LEN: usize = 254;
static EMAIL_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^.+@.+\..{2,}$").expect("invalid email regex"));

type AppResult<T> = Result<T, AppError>;

#[derive(Deserialize, Serialize, ToSchema)]
pub struct CreateUserInput {
    pub username: String,
    pub name: String,
    pub password: String,
    pub email: Option<String>,
}

#[derive(Clone, Deserialize, Serialize, ToSchema)]
pub struct LoginInput {
    pub username: String,
    pub password: String,
    /// TOTP code or recovery code, required on the second step of login for users who have
    /// activated MFA. Absent on the first step.
    #[serde(default)]
    pub totp_code: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub name: String,
    /// Manually-created users don't need an email address, but it's always nice to have one.
    pub email: Option<String>,
    /// Whether the account can authenticate. Deactivated users stay in the DB so they can be
    /// reactivated without losing authenticators, roles, or audit history.
    pub active: bool,
    /// Unix epoch seconds, set when the row is first inserted.
    pub created_at: i64,
    /// Unix epoch seconds. Refreshed on every persisted write.
    pub updated_at: i64,
}

fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as i64
}

impl User {
    pub fn new(username: String, name: String, email: Option<String>) -> User {
        let now = now_epoch();
        User {
            id: Uuid::now_v7(),
            username,
            name,
            email,
            active: true,
            created_at: now,
            updated_at: now,
        }
    }

    /// Get all role names for this user
    pub async fn get_roles(&self, conn: &mut SqliteConnection) -> AppResult<Vec<String>> {
        let roles = sqlx::query_scalar!(
            r#"SELECT r.name FROM roles r
               INNER JOIN user_roles ur ON ur.role_id = r.id
               WHERE ur.user_id = ?"#,
            self.id
        )
        .fetch_all(conn)
        .await?;

        Ok(roles)
    }

    pub async fn list(conn: &mut SqliteConnection) -> AppResult<Vec<User>> {
        Ok(sqlx::query_as!(
            User,
            r#"SELECT id as "id: uuid::Uuid", name, username, email,
                      active as "active!: bool", created_at, updated_at
               FROM users"#
        )
        .fetch_all(conn)
        .await?)
    }

    pub async fn login(input: LoginInput, conn: &mut SqliteConnection) -> AppResult<Self> {
        if let Some(user) = User::get_by_username(&input.username, conn).await? {
            match Authenticator::try_password_login(&user, input.password, conn).await {
                Ok(()) => Ok(user),
                Err(_) => Err(AppError::AuthenticationRequired),
            }
        } else {
            Authenticator::dummy_password_check();
            Err(AppError::AuthenticationRequired)
        }
    }

    pub fn validate_create_input(input: &CreateUserInput) -> AppResult<()> {
        let errors: Vec<String> = vec![
            User::validate_username(&input.username),
            User::validate_name(&input.name),
            User::validate_email(&input.email),
            Authenticator::validate_password(&input.password),
        ]
        .into_iter()
        .filter_map(Result::err)
        .collect();

        if errors.is_empty() {
            Ok(())
        } else {
            Err(AppError::InputError(errors))
        }
    }

    pub async fn get_by_username(
        username: &str,
        conn: &mut SqliteConnection,
    ) -> AppResult<Option<Self>> {
        Ok(sqlx::query_as!(
            User,
            r#"SELECT id as "id: uuid::Uuid", name, username, email,
                      active as "active!: bool", created_at, updated_at
               FROM users WHERE username = ?"#,
            username
        )
        .fetch_optional(conn)
        .await?)
    }

    pub fn validate_username(username: &str) -> Result<(), String> {
        if username.len() < MIN_USERNAME_LEN || username.len() > MAX_USERNAME_LEN {
            Err(format!(
                "Username must be between {MIN_USERNAME_LEN} and {MAX_USERNAME_LEN} characters"
            ))
        } else {
            // Don't run regex on arbitrarily long strings
            if !USERNAME_REGEX.is_match(username) {
                Err(String::from(
                    "Username must consist only of letters, numbers, and allowed symbols",
                ))
            } else {
                Ok(())
            }
        }
    }

    pub fn validate_name(name: &str) -> Result<(), String> {
        if name.len() < MIN_NAME_LEN || name.len() > MAX_NAME_LEN {
            Err(format!(
                "Name must be between {MIN_NAME_LEN} and {MAX_NAME_LEN} characters"
            ))
        } else {
            Ok(())
        }
    }

    pub fn validate_email(email: &Option<String>) -> Result<(), String> {
        match email {
            None => Ok(()),
            Some(email) if email.len() > MAX_EMAIL_LEN => Err(format!(
                "Email must contain no more than {MAX_EMAIL_LEN} characters"
            )),
            Some(email) if EMAIL_REGEX.is_match(email) => Ok(()),
            _ => Err(String::from("Email is not valid")),
        }
    }

    pub async fn update(
        &mut self,
        name: Option<String>,
        email: Option<Option<String>>,
        username: Option<String>,
        conn: &mut SqliteConnection,
    ) -> AppResult<()> {
        if let Some(ref n) = name { Self::validate_name(n).map_err(|e| AppError::InputError(vec![e]))?; }
        if let Some(ref e) = email { Self::validate_email(e).map_err(|e| AppError::InputError(vec![e]))?; }
        if let Some(ref u) = username { Self::validate_username(u).map_err(|e| AppError::InputError(vec![e]))?; }

        if let Some(n) = name { self.name = n; }
        if let Some(e) = email { self.email = e; }
        if let Some(u) = username { self.username = u; }

        self.updated_at = now_epoch();

        sqlx::query!(
            "UPDATE users SET name = ?, email = ?, username = ?, updated_at = ? WHERE id = ?",
            self.name, self.email, self.username, self.updated_at, self.id
        )
        .execute(conn)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(ref db) if db.message().contains("UNIQUE") =>
                AppError::UniqueError("Username already taken".to_string()),
            _ => e.into(),
        })?;
        Ok(())
    }

    /// Flip the `active` flag. Returns `Ok(true)` if the active state actually changed, `Ok(false)`
    /// if it was already in that state. Does NOT revoke tokens; callers that need to cut off
    /// active sessions must call `revoke_all_user_tokens` separately.
    pub async fn set_active(
        &mut self,
        active: bool,
        conn: &mut SqliteConnection,
    ) -> AppResult<bool> {
        if self.active == active {
            return Ok(false);
        }
        self.active = active;
        self.updated_at = now_epoch();
        sqlx::query!(
            "UPDATE users SET active = ?, updated_at = ? WHERE id = ?",
            self.active, self.updated_at, self.id
        )
        .execute(conn)
        .await?;
        Ok(true)
    }

    pub async fn delete(id: Uuid, conn: &mut SqliteConnection) -> AppResult<bool> {
        let result = sqlx::query!("DELETE FROM users WHERE id = ?", id)
            .execute(conn)
            .await?;
        Ok(result.rows_affected() == 1)
    }
}

impl DbEntity for User {
    async fn save(&self, conn: &mut SqliteConnection) -> AppResult<()> {
        sqlx::query!(
            "INSERT INTO users (id, username, name, email, active, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
            self.id,
            self.username,
            self.name,
            self.email,
            self.active,
            self.created_at,
            self.updated_at,
        )
        .execute(conn)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(ref db) if db.message().contains("UNIQUE") => {
                AppError::UniqueError("Username already taken".to_string())
            }
            _ => e.into(),
        })?;

        Ok(())
    }

    async fn get(id: uuid::Uuid, conn: &mut SqliteConnection) -> AppResult<Option<Self>> {
        Ok(sqlx::query_as!(
            User,
            r#"SELECT id as "id: uuid::Uuid", username, name, email,
                      active as "active!: bool", created_at, updated_at
               FROM users WHERE id = ?"#,
            id
        )
        .fetch_optional(conn)
        .await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_username_pattern() {
        let bad_username = String::from("user!");
        let got =
            User::validate_username(&bad_username).expect_err("validate_username is not err!");

        assert_eq!(
            "Username must consist only of letters, numbers, and allowed symbols",
            got
        );
    }

    #[test]
    fn validate_username_length() {
        let short_username = (0..MIN_USERNAME_LEN - 1).map(|_| "a").collect::<String>();
        let got =
            User::validate_username(&short_username).expect_err("validate_username is not err!");
        assert_eq!(
            format!(
                "Username must be between {MIN_USERNAME_LEN} and {MAX_USERNAME_LEN} characters"
            ),
            got
        );

        let long_username = (0..MAX_USERNAME_LEN + 1).map(|_| "a").collect::<String>();
        let got =
            User::validate_username(&long_username).expect_err("validate_username is not err!");
        assert_eq!(
            format!(
                "Username must be between {MIN_USERNAME_LEN} and {MAX_USERNAME_LEN} characters"
            ),
            got
        );
    }

    #[test]
    fn validate_username_ok() {
        let min_username = (0..MIN_USERNAME_LEN).map(|_| "a").collect::<String>();
        User::validate_username(&min_username).expect("validate_username is not ok!");
        let max_username = (0..MAX_USERNAME_LEN).map(|_| "a").collect::<String>();
        User::validate_username(&max_username).expect("validate_username is not ok!");

        let symbol_username = String::from("_abcdefghijklmnopqrstuvwxyz.1234567890-");
        User::validate_username(&symbol_username).expect("validate_username is not ok!");
    }

    #[test]
    fn validate_name_length() {
        let short_name = (0..MIN_NAME_LEN - 1).map(|_| "a").collect::<String>();
        let got = User::validate_name(&short_name).expect_err("validate_name is not err!");
        assert_eq!(
            format!("Name must be between {MIN_NAME_LEN} and {MAX_NAME_LEN} characters"),
            got
        );

        let long_name = (0..MAX_NAME_LEN + 1).map(|_| "a").collect::<String>();
        let got = User::validate_name(&long_name).expect_err("validate_name is not err!");
        assert_eq!(
            format!("Name must be between {MIN_NAME_LEN} and {MAX_NAME_LEN} characters"),
            got
        );
    }

    #[test]
    fn validate_name_ok() {
        let min_name = (0..MIN_NAME_LEN).map(|_| "a").collect::<String>();
        User::validate_name(&min_name).expect("validate_name is not ok!");

        let max_name = (0..MAX_NAME_LEN).map(|_| "a").collect::<String>();
        User::validate_name(&max_name).expect("validate_name is not ok!");

        let realistic_name = String::from("Jane Ivey");
        User::validate_name(&realistic_name).expect("validate_name is not ok!");
    }

    #[test]
    fn validate_email_len() {
        // Just trying to test length validation here, but we should test an OK email too, so
        // include all the necessary parts.
        //
        // It's not enforced by the application, but the localpart should technically not exceed 64
        // characters.
        let max_email_inbox = (0..64).map(|_| "a").collect::<String>();
        let max_email_host = (0..186).map(|_| "a").collect::<String>();
        let max_email = format!("{max_email_inbox}@{max_email_host}.co");
        let long_email = format!("x{max_email}");

        let got = User::validate_email(&Some(long_email)).expect_err("validate_email is not err!");
        assert_eq!(
            format!("Email must contain no more than {MAX_EMAIL_LEN} characters"),
            got
        );

        User::validate_email(&Some(max_email)).expect("validate_email is not ok!");
    }

    #[test]
    fn validate_email_pattern() {
        let no_dot = String::from("me@localhost");
        let no_at = String::from("me.com");
        let no_tld = String::from("me@localhost.");
        let no_host = String::from("me@.com");
        let no_inbox = String::from("@me.com");
        let bad_emails = vec![no_dot, no_at, no_tld, no_host, no_inbox];

        let ok_minimal = String::from("m@e.co");
        let ok_realistic = String::from("hello@authere.jacksn.dev");
        let ok_emails = vec![ok_minimal, ok_realistic];

        for email in bad_emails {
            let got = User::validate_email(&Some(email)).expect_err("validate_email is not err!");
            assert_eq!(String::from("Email is not valid"), got);
        }

        for email in ok_emails {
            User::validate_email(&Some(email)).expect("validate_email is not ok!");
        }

        // Missing emails should always be treated as valid
        User::validate_email(&None).expect("validate_email is not ok!");
    }

    #[test]
    fn validate_input_ok() {
        let input = CreateUserInput {
            username: String::from("user"),
            name: String::from("Test User"),
            email: Some(String::from("hello@authere.jacksn.dev")),
            password: String::from("hunter2hunter2"),
        };

        User::validate_create_input(&input).expect("validate_input is not ok!");
    }

    #[test]
    fn validate_input_errors() {
        let input = CreateUserInput {
            username: String::from(""),
            name: String::from(""),
            email: Some(String::from("")),
            password: String::from(""),
        };

        let got = User::validate_create_input(&input).expect_err("validate_input is not err!");
        let AppError::InputError(errs) = got else {
            panic!("Error type was not InputError!");
        };
        // Messages are tested elsewhere, just make sure we're collecting something here.
        assert_eq!(4, errs.len());
    }

    #[test]
    fn user_new_generates_id() {
        let u1 = User::new("alice".into(), "Alice".into(), None);
        let u2 = User::new("bob".into(), "Bob".into(), None);
        assert_ne!(u1.id, u2.id);
    }

    #[test]
    fn user_new_stores_fields() {
        let user = User::new(
            "alice".into(),
            "Alice Smith".into(),
            Some("alice@test.com".into()),
        );
        assert_eq!(user.username, "alice");
        assert_eq!(user.name, "Alice Smith");
        assert_eq!(user.email, Some("alice@test.com".into()));
    }

    #[test]
    fn user_new_defaults_active() {
        let user = User::new("carol".into(), "Carol".into(), None);
        assert!(user.active, "new users should default to active");
    }

    #[test]
    fn user_new_sets_timestamps() {
        let user = User::new("dan".into(), "Dan".into(), None);
        assert!(user.created_at > 0);
        assert_eq!(user.created_at, user.updated_at);
    }

    #[test]
    fn user_new_no_email() {
        let user = User::new("bob".into(), "Bob".into(), None);
        assert!(user.email.is_none());
    }

    #[test]
    fn user_serialization_roundtrip() {
        let user = User::new("test".into(), "Test User".into(), Some("t@t.co".into()));
        let json = serde_json::to_string(&user).unwrap();
        let deserialized: User = serde_json::from_str(&json).unwrap();
        assert_eq!(user.id, deserialized.id);
        assert_eq!(user.username, deserialized.username);
        assert_eq!(user.name, deserialized.name);
        assert_eq!(user.email, deserialized.email);
        assert_eq!(user.active, deserialized.active);
        assert_eq!(user.created_at, deserialized.created_at);
        assert_eq!(user.updated_at, deserialized.updated_at);
    }

    #[test]
    fn validate_input_no_email_is_ok() {
        let input = CreateUserInput {
            username: String::from("user"),
            name: String::from("Test User"),
            email: None,
            password: String::from("hunter2hunter2"),
        };
        User::validate_create_input(&input).expect("should be valid without email");
    }

    #[test]
    fn validate_username_dots_and_dashes() {
        User::validate_username("user.name-123").unwrap();
    }

    #[test]
    fn validate_username_uppercase() {
        User::validate_username("UserName").unwrap();
    }

    #[test]
    fn validate_username_only_numbers() {
        User::validate_username("12345").unwrap();
    }

    #[test]
    fn validate_email_subdomain() {
        User::validate_email(&Some("user@mail.example.co.uk".into())).unwrap();
    }

    #[test]
    fn validate_email_plus_addressing() {
        User::validate_email(&Some("user+tag@example.com".into())).unwrap();
    }

    // ------------------------------------------------------------------------
    // DB-backed tests exercise the `active` and timestamp columns end to end.
    // Mirrors the in-memory pool pattern from app_passwords.
    // ------------------------------------------------------------------------

    use sqlx::SqlitePool;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn in_memory_pool() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        sqlx::migrate!("../migrations")
            .run(&pool)
            .await
            .expect("run migrations");
        pool
    }

    #[tokio::test]
    async fn save_and_get_preserves_fields() {
        let pool = in_memory_pool().await;
        let mut conn = pool.acquire().await.unwrap();
        let user = User::new("alice".into(), "Alice".into(), Some("a@b.co".into()));
        user.save(&mut conn).await.unwrap();

        let loaded = User::get(user.id, &mut conn).await.unwrap().unwrap();
        assert!(loaded.active);
        assert_eq!(loaded.created_at, user.created_at);
        assert_eq!(loaded.updated_at, user.updated_at);
    }

    #[tokio::test]
    async fn set_active_returns_false_when_unchanged() {
        let pool = in_memory_pool().await;
        let mut conn = pool.acquire().await.unwrap();
        let mut user = User::new("a".into(), "Alice".into(), None);
        user.save(&mut conn).await.unwrap();

        let changed = user.set_active(true, &mut conn).await.unwrap();
        assert!(!changed, "setting active to current value is a no-op");
    }

    #[tokio::test]
    async fn set_active_deactivates_and_refreshes_updated_at() {
        let pool = in_memory_pool().await;
        let mut conn = pool.acquire().await.unwrap();
        let mut user = User::new("a".into(), "Alice".into(), None);
        let original_updated = user.updated_at;
        user.save(&mut conn).await.unwrap();

        // Sleep 1s so unixepoch() granularity picks up a new timestamp.
        std::thread::sleep(std::time::Duration::from_secs(1));
        let changed = user.set_active(false, &mut conn).await.unwrap();
        assert!(changed);
        assert!(!user.active);
        assert!(user.updated_at > original_updated);

        let reloaded = User::get(user.id, &mut conn).await.unwrap().unwrap();
        assert!(!reloaded.active);
    }

    #[tokio::test]
    async fn delete_removes_user() {
        let pool = in_memory_pool().await;
        let mut conn = pool.acquire().await.unwrap();
        let user = User::new("a".into(), "Alice".into(), None);
        user.save(&mut conn).await.unwrap();

        assert!(User::delete(user.id, &mut conn).await.unwrap());
        assert!(User::get(user.id, &mut conn).await.unwrap().is_none());
        // Second delete is a no-op.
        assert!(!User::delete(user.id, &mut conn).await.unwrap());
    }

    #[tokio::test]
    async fn update_refreshes_updated_at() {
        let pool = in_memory_pool().await;
        let mut conn = pool.acquire().await.unwrap();
        let mut user = User::new("a".into(), "Alice".into(), None);
        let original = user.updated_at;
        user.save(&mut conn).await.unwrap();

        std::thread::sleep(std::time::Duration::from_secs(1));
        user.update(Some("Alice New".into()), None, None, &mut conn)
            .await
            .unwrap();
        assert!(user.updated_at > original);
    }

    #[tokio::test]
    async fn login_rejects_inactive_user() {
        let pool = in_memory_pool().await;
        let mut conn = pool.acquire().await.unwrap();
        let mut user = User::new("a".into(), "Alice".into(), None);
        user.save(&mut conn).await.unwrap();

        let auth = Authenticator::new_password("hunter2hunter2".into(), user.id).unwrap();
        auth.save(&mut conn).await.unwrap();

        // Control: login works while active.
        Authenticator::try_password_login(&user, "hunter2hunter2".into(), &mut conn)
            .await
            .expect("active user with correct password must succeed");

        user.set_active(false, &mut conn).await.unwrap();
        let err = Authenticator::try_password_login(&user, "hunter2hunter2".into(), &mut conn)
            .await
            .expect_err("inactive user must not be able to log in");
        assert!(matches!(err, AppError::AuthenticationRequired));
    }

    #[tokio::test]
    async fn list_includes_inactive_users() {
        // Listing returns deactivated users so admins can re-enable them.
        let pool = in_memory_pool().await;
        let mut conn = pool.acquire().await.unwrap();
        let mut alice = User::new("alice".into(), "Alice".into(), None);
        alice.save(&mut conn).await.unwrap();
        let bob = User::new("bob".into(), "Bob".into(), None);
        bob.save(&mut conn).await.unwrap();
        alice.set_active(false, &mut conn).await.unwrap();

        let all = User::list(&mut conn).await.unwrap();
        assert_eq!(all.len(), 2);
        assert!(all.iter().any(|u| !u.active));
    }
}

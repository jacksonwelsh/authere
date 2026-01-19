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

#[derive(Deserialize, Serialize, ToSchema)]
pub struct LoginInput {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
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
            r#"SELECT id as "id: uuid::Uuid", name, username, email FROM users"#
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

    async fn get_by_username(
        username: &str,
        conn: &mut SqliteConnection,
    ) -> AppResult<Option<Self>> {
        Ok(sqlx::query_as!(
            User,
            r#"SELECT id as "id: uuid::Uuid", name, username, email FROM users WHERE username = ?"#,
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
}

impl DbEntity for User {
    async fn save(&self, conn: &mut SqliteConnection) -> AppResult<()> {
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

    async fn get(id: uuid::Uuid, conn: &mut SqliteConnection) -> AppResult<Option<Self>> {
        Ok(sqlx::query_as!(
            User,
            r#"SELECT id as "id: uuid::Uuid", username, name, email FROM users WHERE id = ?"#,
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
}

pub mod auth;

use crate::db::DbEntity;
use crate::errors::AppError;

use regex::Regex;
use serde::{Deserialize, Serialize};
use sqlx::SqliteConnection;
use utoipa::ToSchema;
use uuid::Uuid;

const USERNAME_PATTERN: &'static str = r"^[A-Za-z0-9.\-_]*$";
const MIN_USERNAME_LEN: usize = 3;
const MAX_USERNAME_LEN: usize = 64;

const MIN_NAME_LEN: usize = 3;
const MAX_NAME_LEN: usize = 128;

/// Specified by RFC 3936 errata
const MAX_EMAIL_LEN: usize = 254;

const EMAIL_PATTERN: &'static str = r"^.+@.+\..{2,}$";

type Result<T> = core::result::Result<T, AppError>;

#[derive(Deserialize, Serialize, ToSchema)]
pub struct CreateUserInput {
    pub username: String,
    pub name: String,
    pub password: String,
    pub email: Option<String>,
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

    pub async fn list(conn: &mut SqliteConnection) -> Result<Vec<User>> {
        Ok(sqlx::query_as!(
            User,
            r#"SELECT id as "id: uuid::Uuid", name, username, email FROM users"#
        )
        .fetch_all(conn)
        .await?)
    }

    pub fn validate_input(input: &CreateUserInput) -> Result<Vec<String>> {
        let mut errors = Vec::new();
        if let Some(username_err) = User::validate_username(&input.username)? {
            errors.push(username_err);
        }
        if let Some(name_err) = User::validate_name(&input.name)? {
            errors.push(name_err);
        }
        if let Some(email_err) = User::validate_email(&input.email)? {
            errors.push(email_err);
        }

        Ok(errors)
    }

    fn validate_username(username: &String) -> Result<Option<String>> {
        Ok(
            if username.len() < MIN_USERNAME_LEN || username.len() > MAX_USERNAME_LEN {
                Some(format!(
                    "Username must be between {MIN_USERNAME_LEN} and {MAX_USERNAME_LEN} characters"
                ))
            } else {
                // Don't run regex on arbitrarily long strings
                let username_regex = Regex::new(USERNAME_PATTERN)?;
                if !username_regex.is_match(username) {
                    Some(String::from(
                        "Username must consist only of letters, numbers, and allowed symbols",
                    ))
                } else {
                    None
                }
            },
        )
    }

    fn validate_name(name: &String) -> Result<Option<String>> {
        Ok(if name.len() < MIN_NAME_LEN || name.len() > MAX_NAME_LEN {
            Some(format!(
                "Name must be between {MIN_NAME_LEN} and {MAX_NAME_LEN} characters"
            ))
        } else {
            None
        })
    }

    fn validate_email(email: &Option<String>) -> Result<Option<String>> {
        Ok(match email {
            None => None,
            Some(email) if email.len() > MAX_EMAIL_LEN => Some(format!(
                "Email must contain no more than {MAX_EMAIL_LEN} characters"
            )),
            Some(email) if Regex::new(EMAIL_PATTERN)?.is_match(email) => None,
            _ => Some(String::from("Email is not valid")),
        })
    }
}

impl DbEntity for User {
    async fn save(&self, conn: &mut SqliteConnection) -> Result<()> {
        let id = self.id.to_string();
        sqlx::query!(
            "INSERT INTO users (id, username, name, email) VALUES (?, ?, ?, ?)",
            id,
            self.username,
            self.name,
            self.email
        )
        .execute(conn)
        .await?;

        Ok(())
    }

    async fn get(id: uuid::Uuid, conn: &mut SqliteConnection) -> Result<Option<Self>> {
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
        let got = User::validate_username(&bad_username)
            .expect("validate_username is not ok!")
            .expect("validate_username is not some!");

        assert_eq!(
            "Username must consist only of letters, numbers, and allowed symbols",
            got
        );
    }

    #[test]
    fn validate_username_length() {
        let short_username = (0..MIN_USERNAME_LEN - 1).map(|_| "a").collect::<String>();
        let got = User::validate_username(&short_username)
            .expect("validate_username is not ok!")
            .expect("validate_username is not some!");
        assert_eq!(
            format!(
                "Username must be between {MIN_USERNAME_LEN} and {MAX_USERNAME_LEN} characters"
            ),
            got
        );

        let long_username = (0..MAX_USERNAME_LEN + 1).map(|_| "a").collect::<String>();
        let got = User::validate_username(&long_username)
            .expect("validate_username is not ok!")
            .expect("validate_username is not some!");
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
        assert!(
            User::validate_username(&min_username)
                .expect("validate_username is not ok!")
                .is_none()
        );
        let max_username = (0..MAX_USERNAME_LEN).map(|_| "a").collect::<String>();
        assert!(
            User::validate_username(&max_username)
                .expect("validate_username is not ok!")
                .is_none()
        );

        let symbol_username = String::from("_abcdefghijklmnopqrstuvwxyz.1234567890-");
        assert!(
            User::validate_username(&symbol_username)
                .expect("validate_username is not ok!")
                .is_none()
        );
    }

    #[test]
    fn validate_name_length() {
        let short_name = (0..MIN_NAME_LEN - 1).map(|_| "a").collect::<String>();
        let got = User::validate_name(&short_name)
            .expect("validate_name is not ok!")
            .expect("validate_name is not some!");
        assert_eq!(
            format!("Name must be between {MIN_NAME_LEN} and {MAX_NAME_LEN} characters"),
            got
        );

        let long_name = (0..MAX_NAME_LEN + 1).map(|_| "a").collect::<String>();
        let got = User::validate_name(&long_name)
            .expect("validate_name is not ok!")
            .expect("validate_name is not some!");
        assert_eq!(
            format!("Name must be between {MIN_NAME_LEN} and {MAX_NAME_LEN} characters"),
            got
        );
    }

    #[test]
    fn validate_name_ok() {
        let min_name = (0..MIN_NAME_LEN).map(|_| "a").collect::<String>();
        assert!(
            User::validate_name(&min_name)
                .expect("validate_name is not ok!")
                .is_none()
        );

        let max_name = (0..MAX_NAME_LEN).map(|_| "a").collect::<String>();
        assert!(
            User::validate_name(&max_name)
                .expect("validate_name is not ok!")
                .is_none()
        );

        let realistic_name = String::from("Jane Ivey");
        assert!(
            User::validate_name(&realistic_name)
                .expect("validate_name is not ok!")
                .is_none()
        );
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

        let got = User::validate_email(&Some(long_email))
            .expect("validate_email is not ok!")
            .expect("validate_email is not some!");
        assert_eq!(
            format!("Email must contain no more than {MAX_EMAIL_LEN} characters"),
            got
        );

        assert!(
            User::validate_email(&Some(max_email))
                .expect("validate_email is not ok!")
                .is_none()
        );
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
            let got = User::validate_email(&Some(email))
                .expect("validate_email is not ok!")
                .expect("validate_email is not some!");
            assert_eq!(String::from("Email is not valid"), got);
        }

        for email in ok_emails {
            assert!(
                User::validate_email(&Some(email))
                    .expect("validate_email is not ok!")
                    .is_none()
            );
        }

        // Missing emails should always be treated as valid
        assert!(
            User::validate_email(&None)
                .expect("validate_email is not ok!")
                .is_none()
        )
    }

    #[test]
    fn validate_input_ok() {
        let input = CreateUserInput {
            username: String::from("user"),
            name: String::from("Test User"),
            email: Some(String::from("hello@authere.jacksn.dev")),
            password: String::from("hunter2"),
        };

        assert!(
            User::validate_input(&input)
                .expect("validate_input is not ok!")
                .is_empty()
        );
    }

    #[test]
    fn validate_input_errors() {
        let input = CreateUserInput {
            username: String::from(""),
            name: String::from(""),
            email: Some(String::from("")),
            password: String::from(""),
        };

        let got = User::validate_input(&input).expect("validate_input is not ok!");

        // Messages are tested elsewhere, just make sure we're collecting something here.
        assert_eq!(3, got.len());
    }
}

use crate::{db::DbEntity, errors::AppError};

use argon2::{
    Argon2, PasswordHash, PasswordVerifier,
    password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
};
use sqlx::{FromRow, Row, SqliteConnection, sqlite::SqliteRow};
use uuid::Uuid;

const MIN_PASSWORD_LEN: usize = 12;
const MAX_PASSWORD_LEN: usize = 512;

#[derive(thiserror::Error, Debug)]
pub enum AuthenticationError {
    #[error("Mismatched authentication scheme. This method only supports scheme {0:?}")]
    MismatchedAuthenticationScheme(String),
}

#[derive(Debug)]
pub enum AuthenticationScheme {
    /// Simple password authentication. Contains the salted hash of the password.
    Password(String),
    /// TOTP multifactor. Contains the seed.
    Totp(String),
    // TODO: Implement WebAuthn. Design DB schema with this in mind.
}

pub struct Authenticator {
    pub id: Uuid,
    pub scheme: AuthenticationScheme,
    pub owner_id: Uuid,
}

impl Authenticator {
    pub fn new_password(
        password_cleartext: String,
        owner_id: Uuid,
    ) -> anyhow::Result<Authenticator> {
        let argon2 = Argon2::default();
        let salt = SaltString::generate(&mut OsRng);

        let hash = argon2
            .hash_password(password_cleartext.as_bytes(), &salt)?
            .to_string();

        Ok(Authenticator {
            id: Uuid::now_v7(),
            scheme: AuthenticationScheme::Password(hash),
            owner_id: owner_id,
        })
    }

    pub fn verify_password(&self, input_cleartext: &str) -> anyhow::Result<()> {
        if let AuthenticationScheme::Password(hash) = &self.scheme {
            let argon2 = Argon2::default();
            let hash = PasswordHash::new(&hash)?;
            argon2.verify_password(input_cleartext.as_bytes(), &hash)?;
            Ok(())
        } else {
            Err(
                AuthenticationError::MismatchedAuthenticationScheme(String::from("Password"))
                    .into(),
            )
        }
    }

    pub fn validate_password(password_cleartext: &String) -> Result<Option<String>, AppError> {
        Ok(
            if password_cleartext.len() < MIN_PASSWORD_LEN
                || password_cleartext.len() > MAX_PASSWORD_LEN
            {
                Some(format!(
                    "Password must be between {MIN_PASSWORD_LEN} and {MAX_PASSWORD_LEN} characters"
                ))
            } else {
                None
            },
        )
    }
}

impl DbEntity for Authenticator {
    async fn save(&self, executor: &mut sqlx::SqliteConnection) -> Result<(), AppError> {
        let (auth_type, value) = match &self.scheme {
            AuthenticationScheme::Password(hash) => ("password", hash),
            AuthenticationScheme::Totp(secret) => ("totp", secret),
        };
        let id = self.id.to_string();
        let owner_id = self.owner_id.to_string();
        sqlx::query!(
            "INSERT INTO authenticators(id, type, value, owner_id) VALUES (?, ?, ?, ?)",
            id,
            auth_type,
            value,
            owner_id
        )
        .execute(executor)
        .await?;

        Ok(())
    }

    async fn get(id: uuid::Uuid, conn: &mut SqliteConnection) -> Result<Option<Self>, AppError> {
        // Cannot use macro here as we need the custom FromRow impl which does not work with the
        // macro
        Ok(sqlx::query_as(
                r#"SELECT id as "id: uuid::Uuid", type, value, owner_id FROM authenticators WHERE id = ?"#,
                ).bind(id)
            .fetch_optional(conn)
            .await?)
    }
}

impl<'r> FromRow<'r, SqliteRow> for Authenticator {
    fn from_row(row: &'r SqliteRow) -> Result<Self, sqlx::Error> {
        let id = row.try_get("id")?;
        let scheme_type = row.try_get("type")?;
        let scheme_value = row.try_get("value")?;
        let owner_id = row.try_get("owner_id")?;

        let scheme = match scheme_type {
            "password" => AuthenticationScheme::Password(scheme_value),
            "totp" => AuthenticationScheme::Totp(scheme_value),
            _ => panic!("Invalid authentication scheme"),
        };

        Ok(Authenticator {
            id,
            scheme,
            owner_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_verification() {
        let owner_id = Uuid::now_v7();
        let authenticator = Authenticator::new_password(String::from("hunter2"), owner_id)
            .expect("Authenticator should have been constructed!");

        authenticator.verify_password("hunter2").unwrap();
    }

    #[test]
    fn incorrect_password() {
        let owner_id = Uuid::now_v7();
        let authenticator = Authenticator::new_password(String::from("hunter2"), owner_id)
            .expect("Authenticator should have been constructed!");

        let got = authenticator.verify_password("not-the-password");

        assert!(got.is_err());
    }

    #[test]
    fn cannot_verify_other_authentication_schemes() {
        let authenticator = Authenticator {
            id: Uuid::now_v7(),
            scheme: AuthenticationScheme::Totp(String::from("abc123")),
            owner_id: Uuid::now_v7(),
        };

        assert!(
            authenticator
                .verify_password("password")
                .unwrap_err()
                .downcast_ref::<AuthenticationError>()
                .is_some()
        );
    }

    #[test]
    fn validate_password_len() {
        let short_pw = (0..MIN_PASSWORD_LEN - 1).map(|_| "a").collect::<String>();
        let got = Authenticator::validate_password(&short_pw)
            .expect("validate_password is not ok!")
            .expect("validate_password is not some!");

        let want = format!(
            "Password must be between {MIN_PASSWORD_LEN} and {MAX_PASSWORD_LEN} characters"
        );
        assert_eq!(want, got);

        let long_pw = (0..MAX_PASSWORD_LEN + 1).map(|_| "a").collect::<String>();
        let got = Authenticator::validate_password(&long_pw)
            .expect("validate_password is not ok!")
            .expect("validate_password is not some!");

        assert_eq!(want, got);
    }

    #[test]
    fn validate_password_ok() {
        let min_pw = (0..MIN_PASSWORD_LEN).map(|_| "a").collect::<String>();
        let max_pw = (0..MAX_PASSWORD_LEN).map(|_| "a").collect::<String>();

        assert!(
            Authenticator::validate_password(&min_pw)
                .expect("validate_password is not ok!")
                .is_none()
        );
        assert!(
            Authenticator::validate_password(&max_pw)
                .expect("validate_password is not ok!")
                .is_none()
        );
    }
}

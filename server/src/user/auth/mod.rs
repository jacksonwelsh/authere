use std::sync::LazyLock;

use crate::user::User;
use crate::{db::DbEntity, errors::AppError};

use argon2::{
    Argon2, PasswordHash, PasswordVerifier,
    password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
};
use sqlx::{FromRow, Row, SqliteConnection, sqlite::SqliteRow};
use uuid::Uuid;

pub mod token;

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

#[derive(Debug)]
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
            owner_id,
        })
    }

    pub async fn try_password_login(
        user: &User,
        password_cleartext: String,
        conn: &mut SqliteConnection,
    ) -> Result<(), AppError> {
        if !user.active {
            // Still run the dummy check so timing doesn't leak the active flag.
            Authenticator::dummy_password_check();
            return Err(AppError::AuthenticationRequired);
        }
        if let Some(password) = Authenticator::get_password_for(user, conn).await? {
            match password.verify_password(&password_cleartext) {
                Ok(()) => Ok(()),
                Err(_) => Err(AppError::AuthenticationRequired),
            }
        } else {
            Err(AppError::AuthenticationRequired)
        }
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

    /// Perform a dummy Argon2 verify to prevent timing side-channels on login
    /// when the requested user does not exist.
    pub fn dummy_password_check() {
        static DUMMY_HASH: LazyLock<String> = LazyLock::new(|| {
            let argon2 = Argon2::default();
            let salt = SaltString::generate(&mut OsRng);
            argon2
                .hash_password(b"dummy", &salt)
                .expect("Failed to create dummy hash")
                .to_string()
        });
        let hash = PasswordHash::new(&DUMMY_HASH).expect("Failed to parse dummy hash");
        let _ = Argon2::default().verify_password(b"not-the-password", &hash);
    }

    pub fn validate_password(password_cleartext: &str) -> Result<(), String> {
        if password_cleartext.len() < MIN_PASSWORD_LEN
            || password_cleartext.len() > MAX_PASSWORD_LEN
        {
            Err(format!(
                "Password must be between {MIN_PASSWORD_LEN} and {MAX_PASSWORD_LEN} characters"
            ))
        } else {
            Ok(())
        }
    }

    pub async fn update_password(
        user_id: Uuid,
        new_password: String,
        conn: &mut SqliteConnection,
    ) -> Result<(), AppError> {
        let new_auth = Authenticator::new_password(new_password, user_id)
            .map_err(|e| AppError::InternalError(format!("Failed to hash password: {e}")))?;
        let AuthenticationScheme::Password(hash) = new_auth.scheme else {
            return Err(AppError::InternalError("Unexpected scheme".into()));
        };
        sqlx::query!(
            "UPDATE authenticators SET value = ? WHERE owner_id = ? AND type = 'password'",
            hash,
            user_id
        )
        .execute(conn)
        .await?;
        Ok(())
    }

    async fn get_password_for(
        user: &User,
        conn: &mut SqliteConnection,
    ) -> Result<Option<Authenticator>, AppError> {
        Ok(
            sqlx::query_as(
                r#"SELECT id, type, value, owner_id FROM authenticators WHERE owner_id = ? AND type = 'password'"#)
            .bind(user.id)
            .fetch_optional(conn)
            .await?
        )
    }
}

impl DbEntity for Authenticator {
    async fn save(&self, executor: &mut sqlx::SqliteConnection) -> Result<(), AppError> {
        let (auth_type, value) = match &self.scheme {
            AuthenticationScheme::Password(hash) => ("password", hash),
            AuthenticationScheme::Totp(secret) => ("totp", secret),
        };
        sqlx::query!(
            "INSERT INTO authenticators(id, type, value, owner_id) VALUES (?, ?, ?, ?)",
            self.id,
            auth_type,
            value,
            self.owner_id
        )
        .execute(executor)
        .await?;

        Ok(())
    }

    async fn get(id: uuid::Uuid, conn: &mut SqliteConnection) -> Result<Option<Self>, AppError> {
        // Cannot use macro here as we need the custom FromRow impl which does not work with the
        // macro
        Ok(
            sqlx::query_as(r#"SELECT id, type, value, owner_id FROM authenticators WHERE id = ?"#)
                .bind(id)
                .fetch_optional(conn)
                .await?,
        )
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
            other => {
                return Err(sqlx::Error::ColumnDecode {
                    index: "type".to_string(),
                    source: Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Unknown authentication scheme: {other}"),
                    )),
                });
            }
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
        let got =
            Authenticator::validate_password(&short_pw).expect_err("validate_password is not err!");

        let want = format!(
            "Password must be between {MIN_PASSWORD_LEN} and {MAX_PASSWORD_LEN} characters"
        );
        assert_eq!(want, got);

        let long_pw = (0..MAX_PASSWORD_LEN + 1).map(|_| "a").collect::<String>();
        let got =
            Authenticator::validate_password(&long_pw).expect_err("validate_password is not err!");

        assert_eq!(want, got);
    }

    #[test]
    fn validate_password_ok() {
        let min_pw = (0..MIN_PASSWORD_LEN).map(|_| "a").collect::<String>();
        let max_pw = (0..MAX_PASSWORD_LEN).map(|_| "a").collect::<String>();

        Authenticator::validate_password(&min_pw).expect("validate_password is not ok!");
        Authenticator::validate_password(&max_pw).expect("validate_password is not ok!");
    }

    #[test]
    fn dummy_password_check_does_not_panic() {
        Authenticator::dummy_password_check();
        Authenticator::dummy_password_check();
    }

    #[test]
    fn new_password_authenticator_has_correct_fields() {
        let owner_id = Uuid::now_v7();
        let auth = Authenticator::new_password("valid_password_12".into(), owner_id).unwrap();
        assert_eq!(auth.owner_id, owner_id);
        assert!(matches!(auth.scheme, AuthenticationScheme::Password(_)));
    }

    #[test]
    fn new_password_produces_unique_hashes() {
        let owner_id = Uuid::now_v7();
        let a1 = Authenticator::new_password("same_password_12".into(), owner_id).unwrap();
        let a2 = Authenticator::new_password("same_password_12".into(), owner_id).unwrap();

        let h1 = match &a1.scheme {
            AuthenticationScheme::Password(h) => h.clone(),
            _ => panic!("wrong scheme"),
        };
        let h2 = match &a2.scheme {
            AuthenticationScheme::Password(h) => h.clone(),
            _ => panic!("wrong scheme"),
        };
        assert_ne!(h1, h2, "different salts should produce different hashes");
    }

    #[test]
    fn new_password_generates_unique_ids() {
        let owner = Uuid::now_v7();
        let a1 = Authenticator::new_password("password1234".into(), owner).unwrap();
        let a2 = Authenticator::new_password("password1234".into(), owner).unwrap();
        assert_ne!(a1.id, a2.id);
    }

    #[test]
    fn verify_password_wrong_scheme() {
        let auth = Authenticator {
            id: Uuid::now_v7(),
            scheme: AuthenticationScheme::Totp("seed123".into()),
            owner_id: Uuid::now_v7(),
        };
        let err = auth.verify_password("anything").unwrap_err();
        assert!(err.downcast_ref::<AuthenticationError>().is_some());
    }

    #[test]
    fn authentication_error_display() {
        let err = AuthenticationError::MismatchedAuthenticationScheme("Password".into());
        let msg = format!("{err}");
        assert!(msg.contains("Password"));
    }
}

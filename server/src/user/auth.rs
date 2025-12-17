use anyhow::Result;
use argon2::{
    Argon2, PasswordHash, PasswordVerifier,
    password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
};
use uuid::Uuid;

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
    pub scheme: AuthenticationScheme,
    pub owner_id: Uuid,
}

impl Authenticator {
    pub fn new_password(password_cleartext: String, owner_id: Uuid) -> Result<Authenticator> {
        let argon2 = Argon2::default();
        let salt = SaltString::generate(&mut OsRng);

        let hash = argon2
            .hash_password(password_cleartext.as_bytes(), &salt)?
            .to_string();

        Ok(Authenticator {
            scheme: AuthenticationScheme::Password(hash),
            owner_id: owner_id,
        })
    }

    pub fn verify_password(&self, input_cleartext: &str) -> Result<()> {
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
}

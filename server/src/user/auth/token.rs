use crate::{errors::AppError, user::User};

use axum::routing::get_service;
use sqlx::query;
use uuid::Uuid;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use sqlx::SqliteConnection;

pub struct Claims {
    sub: String,
    roles: Vec<String>,
}

fn generate_key() -> SigningKey {
    let mut rng = OsRng;
    SigningKey::generate(&mut rng)
}

/// Initializes the database with a signing key if not present. Returns Ok(true) if work was done,
/// Ok(false) otherwise.
pub async fn try_initialize(conn: &mut SqliteConnection) -> Result<bool, AppError> {
    let existing_key = query!("SELECT id FROM keys WHERE name = 'default'")
        .fetch_optional(&mut *conn)
        .await?;
    match existing_key {
        Some(_) => Ok(false),
        None => {
            initialize(conn).await?;
            Ok(true)
        }
    }
}

async fn initialize(conn: &mut SqliteConnection) -> Result<(), AppError> {
    let key = generate_key();

    let id = Uuid::now_v7();
    let public_key = key.verifying_key().to_bytes();
    let private_key = key.to_bytes();

    let pubk_slice = &public_key[..];
    let privk_slice = &private_key[..];

    query!(
        "INSERT INTO keys (id, name, public_key, private_key) VALUES (?, 'default', ?, ?)",
        id,
        pubk_slice,
        privk_slice,
    )
    .execute(conn)
    .await?;

    Ok(())
}

async fn get_secret_key(conn: &mut SqliteConnection) -> Result<SigningKey, AppError> {
    let private_key: [u8; 32] = query!("SELECT private_key FROM keys WHERE name = 'default'")
        .fetch_one(conn)
        .await?
        .private_key
        .try_into()
        .unwrap();

    Ok(SigningKey::from_bytes(&private_key))
}

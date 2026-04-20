use serde::{Deserialize, Serialize};
use sqlx::SqliteConnection;
use utoipa::ToSchema;

use crate::errors::AppError;

#[derive(Debug, Serialize, ToSchema)]
pub struct SettingsResponse {
    pub open_registration: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateSettingsInput {
    pub open_registration: Option<bool>,
}

pub async fn get_setting(key: &str, conn: &mut SqliteConnection) -> Result<Option<String>, AppError> {
    let row = sqlx::query!("SELECT value FROM settings WHERE key = ?", key)
        .fetch_optional(conn)
        .await?;
    Ok(row.map(|r| r.value))
}

pub async fn set_setting(key: &str, value: &str, conn: &mut SqliteConnection) -> Result<(), AppError> {
    sqlx::query!(
        "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
        key,
        value
    )
    .execute(conn)
    .await?;
    Ok(())
}

pub async fn open_registration_enabled(conn: &mut SqliteConnection) -> Result<bool, AppError> {
    let value = get_setting("open_registration", conn).await?;
    Ok(value.as_deref() == Some("true"))
}

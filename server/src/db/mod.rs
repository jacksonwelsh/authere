use crate::errors::AppError;
use sqlx::SqliteConnection;

pub trait DbEntity {
    async fn save(&self, executor: &mut SqliteConnection) -> Result<(), AppError>;
    async fn get(id: uuid::Uuid, conn: &mut SqliteConnection) -> Result<Option<Self>, AppError>
    where
        Self: Sized;
}

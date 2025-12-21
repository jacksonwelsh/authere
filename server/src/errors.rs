use axum::{http::StatusCode, response::IntoResponse};

pub enum AppError {
    DbError(sqlx::Error),
    NotFound,
}

impl From<AppError> for StatusCode {
    fn from(err: AppError) -> Self {
        match err {
            AppError::DbError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::NotFound => StatusCode::NOT_FOUND,
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::DbError(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", err),
            )
                .into_response(),
            Self::NotFound => {
                (StatusCode::NOT_FOUND, String::from("Resource not found")).into_response()
            }
        }
    }
}

impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        AppError::DbError(err)
    }
}

use axum::{http::StatusCode, response::IntoResponse};
use sqlx::error::ErrorKind::UniqueViolation;

#[derive(Debug)]
pub enum AppError {
    /// Unless specially handled, all sqlx errors should resolve to this.
    DbError(sqlx::Error),
    /// Special error for uniqueness constraint failures, as those represent a 4XX. Contained
    /// string must be something user-presentable.
    UniqueError(String),
    NotFound,
    /// Malformed user input. Each problem will have its own entry in the vec.
    InputError(Vec<String>),
    /// User needs to log in. Can also be raised by authn endpoints for invalid credentials.
    AuthenticationRequired,
    // General internal server errors, distinct from those caused directly by the DB.
    InternalError(String),
}

impl From<AppError> for StatusCode {
    fn from(err: AppError) -> Self {
        match err {
            AppError::DbError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::UniqueError(_) => StatusCode::CONFLICT,
            AppError::NotFound => StatusCode::NOT_FOUND,
            AppError::InputError(_) => StatusCode::BAD_REQUEST,
            AppError::AuthenticationRequired => StatusCode::UNAUTHORIZED,
            AppError::InternalError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::DbError(err) => {
                eprintln!("Database error: {}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    String::from("Internal server error"),
                )
                    .into_response()
            }
            Self::InternalError(err) => {
                eprintln!("{}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    String::from("Internal server error"),
                )
                    .into_response()
            }
            Self::NotFound => {
                (StatusCode::NOT_FOUND, String::from("Resource not found")).into_response()
            }
            Self::UniqueError(err) => (StatusCode::CONFLICT, err).into_response(),
            Self::AuthenticationRequired => (
                StatusCode::UNAUTHORIZED,
                String::from("Authentication required"),
            )
                .into_response(),
            Self::InputError(errs) => (StatusCode::BAD_REQUEST, errs.join(", ")).into_response(),
        }
    }
}

impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        // There's other kinds of errors, but the rest should be treated as unrecoverable:
        // application logic should validate inputs before sending to DB.
        if let Some(db_err) = err.as_database_error()
            && matches!(db_err.kind(), UniqueViolation)
        {
            AppError::UniqueError(String::from("Uniqueness constraint not satisfied"))
        } else {
            AppError::DbError(err)
        }
    }
}

impl From<regex::Error> for AppError {
    fn from(err: regex::Error) -> Self {
        AppError::InternalError(err.to_string())
    }
}

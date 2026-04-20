use std::io;
use axum::{http::StatusCode, response::IntoResponse};
use sqlx::error::ErrorKind::UniqueViolation;
use tracing::error;

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
    /// User is authenticated but not authorized for this action.
    Forbidden,
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
            AppError::Forbidden => StatusCode::FORBIDDEN,
            AppError::InternalError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::DbError(err) => {
                error!(error = %err, "database error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    String::from("Internal server error"),
                )
                    .into_response()
            }
            Self::InternalError(err) => {
                error!(error = %err, "internal error");
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
            Self::Forbidden => (
                StatusCode::FORBIDDEN,
                String::from("Access denied"),
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

impl From<io::Error> for AppError {
    fn from(err: io::Error) -> Self {
        AppError::InternalError(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;

    #[test]
    fn status_code_from_db_error() {
        let err = AppError::DbError(sqlx::Error::RowNotFound);
        assert_eq!(StatusCode::from(err), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn status_code_from_unique_error() {
        let err = AppError::UniqueError("dup".into());
        assert_eq!(StatusCode::from(err), StatusCode::CONFLICT);
    }

    #[test]
    fn status_code_from_not_found() {
        assert_eq!(StatusCode::from(AppError::NotFound), StatusCode::NOT_FOUND);
    }

    #[test]
    fn status_code_from_input_error() {
        let err = AppError::InputError(vec!["bad".into()]);
        assert_eq!(StatusCode::from(err), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn status_code_from_authentication_required() {
        assert_eq!(
            StatusCode::from(AppError::AuthenticationRequired),
            StatusCode::UNAUTHORIZED
        );
    }

    #[test]
    fn status_code_from_forbidden() {
        assert_eq!(StatusCode::from(AppError::Forbidden), StatusCode::FORBIDDEN);
    }

    #[test]
    fn status_code_from_internal_error() {
        let err = AppError::InternalError("oops".into());
        assert_eq!(StatusCode::from(err), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn into_response_not_found() {
        let resp = AppError::NotFound.into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn into_response_unique_error() {
        let resp = AppError::UniqueError("already exists".into()).into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[test]
    fn into_response_authentication_required() {
        let resp = AppError::AuthenticationRequired.into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn into_response_forbidden() {
        let resp = AppError::Forbidden.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn into_response_input_error_joins_messages() {
        let resp =
            AppError::InputError(vec!["err1".into(), "err2".into()]).into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn into_response_internal_error() {
        let resp = AppError::InternalError("boom".into()).into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn into_response_db_error() {
        let resp = AppError::DbError(sqlx::Error::RowNotFound).into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn from_sqlx_unique_violation() {
        let db_err = sqlx::Error::Database(Box::new(TestDbError {
            message: "UNIQUE constraint failed".into(),
            is_unique: true,
        }));
        let app_err = AppError::from(db_err);
        assert!(matches!(app_err, AppError::UniqueError(_)));
    }

    #[test]
    fn from_sqlx_other_error() {
        let err = AppError::from(sqlx::Error::RowNotFound);
        assert!(matches!(err, AppError::DbError(_)));
    }

    #[test]
    fn from_regex_error() {
        let err = regex::Regex::new("[invalid").unwrap_err();
        let app_err = AppError::from(err);
        assert!(matches!(app_err, AppError::InternalError(_)));
    }

    #[test]
    fn from_io_error() {
        let err = io::Error::new(io::ErrorKind::NotFound, "gone");
        let app_err = AppError::from(err);
        assert!(matches!(app_err, AppError::InternalError(msg) if msg.contains("gone")));
    }

    struct TestDbError {
        message: String,
        is_unique: bool,
    }

    impl std::fmt::Debug for TestDbError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.message)
        }
    }

    impl std::fmt::Display for TestDbError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.message)
        }
    }

    impl std::error::Error for TestDbError {}

    impl sqlx::error::DatabaseError for TestDbError {
        fn message(&self) -> &str {
            &self.message
        }
        fn kind(&self) -> sqlx::error::ErrorKind {
            if self.is_unique {
                sqlx::error::ErrorKind::UniqueViolation
            } else {
                sqlx::error::ErrorKind::Other
            }
        }
        fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
            self
        }
        fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
            self
        }
        fn into_error(
            self: Box<Self>,
        ) -> Box<dyn std::error::Error + Send + Sync + 'static> {
            self
        }
    }
}

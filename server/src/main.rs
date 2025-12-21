use std::io;

use crate::db::DbEntity;
use crate::errors::AppError;
use crate::user::User;
use crate::user::auth::Authenticator;

use axum::extract::{self, Path, State};
use serde::Deserialize;
use sqlx::SqlitePool;
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use utoipa_swagger_ui::SwaggerUi;
use uuid::Uuid;

const ADMIN_TAG: &str = "admin";
const AUTH_TAG: &str = "auth";

pub mod db;
pub mod errors;
pub mod user;

#[derive(OpenApi)]
#[openapi(
    tags(
        (name = ADMIN_TAG, description = "Admin API endpoints"),
        (name = AUTH_TAG, description = "Authentication API endpoints")
    )
)]
struct ApiDoc;

#[derive(Clone)]
struct AppState {
    db_pool: SqlitePool,
}

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    let db_pool = SqlitePool::connect("sqlite:///Users/jacksonwelsh/code/authere/data.db")
        .await
        .expect("Could not connect to sqlite!");

    // add a single route
    let (router, api) = OpenApiRouter::with_openapi(ApiDoc::openapi())
        .routes(routes!(create_user, get_users))
        .routes(routes!(get_user))
        .with_state(AppState { db_pool })
        .split_for_parts();

    let router = router.merge(SwaggerUi::new("/docs").url("/apidoc/openapi.json", api));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, router).await
}

#[derive(Deserialize)]
struct CreateUserInput {
    username: String,
    name: String,
    password: String,
    email: Option<String>,
}

#[utoipa::path(
    post,
    path = "/user",
    responses(
        (status = 200, description = "Created a new user"),
        (status = 400, description = "Invalid input when creating a new user"),
        (status = 500, description = "Internal error when creating the user"),
    ),
    tag = AUTH_TAG
)]
async fn create_user(
    State(state): State<AppState>,
    extract::Json(payload): extract::Json<CreateUserInput>,
) -> Result<axum::Json<User>, AppError> {
    let user = User::new(payload.username, payload.name, payload.email);
    let authenticator = Authenticator::new_password(payload.password, user.id)
        .expect("Authenticator failed to build!");

    let mut tx = state.db_pool.begin().await?;
    user.save(&mut tx).await?;
    authenticator.save(&mut tx).await?;
    tx.commit().await?;

    Ok(axum::Json(user))
}

#[utoipa::path(
    get,
    path = "/user",
    responses(
        (status = 200, description = "Lists all users on the system"),
        (status = 500, description = "Internal error when listing users"),
    ),
    tag = ADMIN_TAG
)]
async fn get_users(State(state): State<AppState>) -> Result<axum::Json<Vec<User>>, AppError> {
    let mut conn = state.db_pool.acquire().await?;
    let users = User::list(&mut conn).await?;

    Ok(axum::Json(users))
}

#[utoipa::path(
    get,
    path = "/user/{id}",
    responses(
        (status = 200, description = "Retrieved a user"),
        (status = 404, description = "User not found"),
        (status = 500, description = "Internal error when getting user"),
    ),
    tag = ADMIN_TAG
)]
async fn get_user(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<axum::Json<User>, AppError> {
    let mut conn = state.db_pool.acquire().await?;
    let user = User::get(id, &mut conn).await?;

    match user {
        Some(user) => Ok(axum::Json(user)),
        None => Err(AppError::NotFound),
    }
}

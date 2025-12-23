use std::env;
use std::io;

use crate::db::DbEntity;
use crate::errors::AppError;
use crate::user::auth::Authenticator;
use crate::user::{CreateUserInput, LoginInput, User};

use axum::extract::{self, Path, State};
use axum::http::StatusCode;
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
    let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| {
        eprintln!("DATABASE_URL not set, using default: sqlite:./data.db");
        String::from("sqlite:./data.db")
    });
    let db_pool = SqlitePool::connect(&database_url)
        .await
        .expect("Could not connect to sqlite!");

    // add a single route
    let (router, api) = OpenApiRouter::with_openapi(ApiDoc::openapi())
        .routes(routes!(create_user, get_users))
        .routes(routes!(get_user))
        .routes(routes!(login))
        .with_state(AppState { db_pool })
        .split_for_parts();

    let router = router.merge(SwaggerUi::new("/docs").url("/apidoc/openapi.json", api));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, router).await
}

#[utoipa::path(
    post,
    path = "/user",
    responses(
        (status = 201, description = "Created a new user"),
        (status = 400, description = "Invalid input when creating a new user"),
        (status = 409, description = "User with that username already exists"),
        (status = 500, description = "Internal error when creating the user"),
    ),
    request_body(
        content = CreateUserInput,
        example = json!(CreateUserInput {
            username: String::from("bob_burger"),
            name: String::from("Bob Belcher"),
            password: String::from("hunter2hunter2"),
            email: Some(String::from("bob@bobsburgers.net"))
        })
    ),
    tag = AUTH_TAG
)]
async fn create_user(
    State(state): State<AppState>,
    extract::Json(input): extract::Json<CreateUserInput>,
) -> Result<(StatusCode, axum::Json<User>), AppError> {
    User::validate_create_input(&input)?;

    let user = User::new(input.username, input.name, input.email);
    let authenticator = Authenticator::new_password(input.password, user.id).map_err(|e| {
        AppError::InternalError(format!(
            "Failed to create Authenticator for user {user:?} ({e})"
        ))
    })?;

    let mut tx = state.db_pool.begin().await?;
    user.save(&mut tx).await?;
    authenticator.save(&mut tx).await?;
    tx.commit().await?;
    // TODO: implement idempotency

    Ok((StatusCode::CREATED, axum::Json(user)))
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
    params(
        ("id" = Uuid, Path, description = "User ID")
    ),
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

#[utoipa::path(
    post,
    path = "/login",
    request_body(
        content = LoginInput,
        example = json!(LoginInput {
            username: String::from("bob_burger"),
            password: String::from("hunter2hunter2"),
        }),
    ),
    responses(
        (status = 200, description = "Successful login"),
        (status = 400, description = "Invalid username or password"),
        (status = 401, description = "Incorrect username or password"),
        (status = 500, description = "Internal server error")
    ),
    tag = AUTH_TAG,
)]
async fn login(
    State(state): State<AppState>,
    extract::Json(input): extract::Json<LoginInput>,
) -> Result<axum::Json<User>, AppError> {
    // Something to handle later: there's a distinctly different latency between requests where a
    // user is found and a user is not, due to password hashing (10ms vs 300ms). Need to slow down
    // user-not-found requests to deter enumeration attacks, maybe add some jitter to user-found
    // requests too.
    let mut conn = state.db_pool.acquire().await?;
    // Be kind to users, throw a different error if password doesn't meet requirements
    if let Err(msg) = Authenticator::validate_password(&input.password) {
        return Err(AppError::InputError(vec![msg]));
    }
    let user = User::login(input, &mut conn).await?;

    // TODO: return some kind of token here. The user object is effectly useless.
    // Set a cookie?
    Ok(axum::Json(user))
}

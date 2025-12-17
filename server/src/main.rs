use std::io;

use axum::Json;
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use utoipa_swagger_ui::SwaggerUi;

const ADMIN_TAG: &str = "admin";
const AUTH_TAG: &str = "auth";

pub mod user;

#[derive(OpenApi)]
#[openapi(
    tags(
        (name = ADMIN_TAG, description = "Admin API endpoints"),
        (name = AUTH_TAG, description = "Authentication API endpoints")
    )
)]
struct ApiDoc;

#[tokio::main]
async fn main() -> Result<(), io::Error>{
    // add a single route
    let (router, api) = OpenApiRouter::with_openapi(ApiDoc::openapi())
        .routes(routes!(hello_world))
        .split_for_parts();

    let router = router.merge(SwaggerUi::new("/docs").url("/apidoc/openapi.json", api));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, router).await
}

#[utoipa::path(
    get,
    path = "/",
    responses(
        (status = 200, description = "Hello, world!")
    ),
    tag = "admin"
)]
async fn hello_world() -> Json<Vec<String>> {
    Json(vec![String::from("Hello,"), String::from("World!")])
}

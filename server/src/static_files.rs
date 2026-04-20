use axum::{
    body::Body,
    http::{HeaderValue, Response, StatusCode, header},
    response::IntoResponse,
};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "../ui/dist"]
struct Assets;

pub async fn serve_asset(
    axum::extract::Path(path): axum::extract::Path<String>,
) -> impl IntoResponse {
    // Route is /assets/{*path}; embedded files live at assets/<path>
    let full_path = format!("assets/{path}");
    match Assets::get(&full_path) {
        Some(content) => {
            let mime = mime_guess::from_path(&path).first_or_octet_stream();
            Response::builder()
                .status(StatusCode::OK)
                .header(
                    header::CONTENT_TYPE,
                    HeaderValue::from_str(mime.as_ref()).unwrap_or_else(|_| {
                        HeaderValue::from_static("application/octet-stream")
                    }),
                )
                // Long cache for hashed assets
                .header(header::CACHE_CONTROL, "public, max-age=31536000, immutable")
                .body(Body::from(content.data))
                .unwrap()
        }
        None => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("not found"))
            .unwrap(),
    }
}

pub async fn serve_spa() -> impl IntoResponse {
    match Assets::get("index.html") {
        Some(content) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .header(header::CACHE_CONTROL, "no-cache")
            .body(Body::from(content.data))
            .unwrap(),
        None => Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .body(Body::from("UI not built. Run `npm run build` in ui/."))
            .unwrap(),
    }
}

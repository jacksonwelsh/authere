use axum::{
    extract::{Request, State},
    http::{Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};

/// The public auth origin and explicitly trusted browser API clients may make
/// state-changing requests. SameSite cookies alone do not protect against a
/// compromised application on another subdomain of the same site.
#[derive(Clone)]
pub struct BrowserSecurity {
    pub allowed_origins: Vec<String>,
}

pub async fn protect_browser_requests(
    State(config): State<BrowserSecurity>,
    request: Request,
    next: Next,
) -> Response {
    let safe = matches!(
        *request.method(),
        Method::GET | Method::HEAD | Method::OPTIONS
    );
    // RP-initiated logout is also a cross-origin form POST. That handler
    // requires either same-origin confirmation or a browser-bound ID hint.
    let oidc_logout =
        request.method() == Method::POST && request.uri().path() == "/oauth/end_session";
    if !safe && !oidc_logout {
        let headers = request.headers();
        let allowed = match headers.get(header::ORIGIN) {
            Some(origin) => origin.to_str().ok().is_some_and(|origin| {
                origin != "null"
                    && config
                        .allowed_origins
                        .iter()
                        .any(|allowed| allowed == origin)
            }),
            // Non-browser API clients do not send Origin/Fetch Metadata.
            None => headers
                .get("sec-fetch-site")
                .is_none_or(|value| value == "same-origin" || value == "none"),
        };
        if !allowed {
            return (StatusCode::FORBIDDEN, "Untrusted request origin").into_response();
        }
    }
    let sensitive = request.uri().path().starts_with("/api/")
        || request.uri().path().starts_with("/oauth/")
        || request.uri().path().starts_with("/.authere/");
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    headers.insert(header::X_FRAME_OPTIONS, "DENY".parse().unwrap());
    headers.insert(header::REFERRER_POLICY, "no-referrer".parse().unwrap());
    if sensitive {
        headers.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
        headers.insert(header::PRAGMA, "no-cache".parse().unwrap());
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, body::Body, middleware, routing::post};
    use tower::ServiceExt;

    fn router() -> Router {
        Router::new()
            .route("/api/action", post(|| async { StatusCode::NO_CONTENT }))
            .layer(middleware::from_fn_with_state(
                BrowserSecurity {
                    allowed_origins: vec!["https://auth.example.com".into()],
                },
                protect_browser_requests,
            ))
    }

    #[tokio::test]
    async fn blocks_cross_origin_and_opaque_browser_writes() {
        for origin in [
            "https://weak.example.com",
            "https://outside.invalid",
            "null",
        ] {
            let response = router()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/action")
                        .header(header::ORIGIN, origin)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }
        let response = router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/action")
                    .header("sec-fetch-site", "same-site")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn accepts_auth_origin_and_non_browser_clients_without_caching() {
        for origin in [None, Some("https://auth.example.com")] {
            let mut request = Request::builder().method("POST").uri("/api/action");
            if let Some(origin) = origin {
                request = request.header(header::ORIGIN, origin);
            }
            let response = router()
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert_eq!(response.headers()[header::REFERRER_POLICY], "no-referrer");
        }
    }
}

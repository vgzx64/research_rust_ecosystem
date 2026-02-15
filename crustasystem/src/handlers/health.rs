use axum::{http::StatusCode, Json};
use serde::Serialize;
use utoipa::ToSchema;

/// Health check response
#[derive(Serialize, ToSchema)]
pub struct HealthResponse {
    pub status: String,
}

/// Health check handler
#[utoipa::path(
    get,
    path = "/health",
    responses(
        (status = 200, description = "Health check successful", body = HealthResponse)
    )
)]
pub async fn health_check() -> (StatusCode, Json<HealthResponse>) {
    (StatusCode::OK, Json(HealthResponse { status: "OK".to_string() }))
}

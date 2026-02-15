//! Severity levels handlers

use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
};
use sea_orm::EntityTrait;
use serde::Serialize;
use utoipa::ToSchema;

use crate::db::SharedState;
use crate::models::severity_levels;

#[derive(Serialize, ToSchema)]
pub struct SeverityLevelResponse {
    pub id: i32,
    pub name: String,
}

/// List all severity levels
#[utoipa::path(
    get,
    path = "/severity-levels",
    responses(
        (status = 200, description = "List of severity levels", body = [SeverityLevelResponse])
    )
)]
#[axum_macros::debug_handler]
pub async fn list(
    State(state): State<SharedState>,
) -> Result<Json<Vec<severity_levels::Model>>, StatusCode> {
    tracing::debug!("Fetching severity levels...");
    let levels = severity_levels::Entity::find()
        .all(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("Database error: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    
    tracing::debug!("Found {} severity levels", levels.len());
    Ok(Json(levels))
}

//! Severity levels handlers

use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
};
use sea_orm::EntityTrait;

use crate::db::SharedState;
use crate::models::severity_levels;

pub async fn list(
    State(state): State<SharedState>,
) -> Result<Json<Vec<severity_levels::Model>>, StatusCode> {
    let levels = severity_levels::Entity::find()
        .all(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    Ok(Json(levels))
}

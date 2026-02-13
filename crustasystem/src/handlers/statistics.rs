//! Statistics handlers

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use sea_orm::EntityTrait;

use crate::db::SharedState;
use crate::models::vulnerability_statistics;

pub async fn get_by_vulnerability(
    State(state): State<SharedState>,
    Path(id): Path<i32>,
) -> Result<Json<vulnerability_statistics::Model>, StatusCode> {
    let stats = vulnerability_statistics::Entity::find_by_id(id)
        .one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    
    Ok(Json(stats))
}

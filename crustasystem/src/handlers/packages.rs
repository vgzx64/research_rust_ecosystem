//! Packages handlers

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use sea_orm::{EntityTrait, QueryFilter, ColumnTrait};

use crate::db::SharedState;
use crate::models::packages;

pub async fn get_by_name(
    State(state): State<SharedState>,
    Path(name): Path<String>,
) -> Result<Json<packages::Model>, StatusCode> {
    let pkg = packages::Entity::find()
        .filter(packages::Column::Name.eq(&name))
        .one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    
    Ok(Json(pkg))
}

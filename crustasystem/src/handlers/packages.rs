//! Packages handlers

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use sea_orm::{EntityTrait, QueryFilter, ColumnTrait};
use serde::Serialize;
use utoipa::ToSchema;

use crate::db::SharedState;
use crate::models::packages;

#[derive(Serialize, ToSchema)]
pub struct PackageResponse {
    pub id: i32,
    pub name: String,
    pub ecosystem: Option<String>,
}

/// Get a package by name
#[utoipa::path(
    get,
    path = "/packages/{name}",
    responses(
        (status = 200, description = "Package found", body = PackageResponse),
        (status = 404, description = "Package not found")
    )
)]
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

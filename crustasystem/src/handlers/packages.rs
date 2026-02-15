//! Packages handlers

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use sea_orm::{EntityTrait, QueryFilter, ColumnTrait, ActiveModelTrait};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::db::SharedState;
use crate::models::packages;

#[derive(Serialize, ToSchema)]
pub struct PackageResponse {
    pub id: i32,
    pub name: String,
    pub ecosystem: Option<String>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct CreatePackageRequest {
    pub name: String,
    #[serde(default)]
    pub repository_url: Option<String>,
    #[serde(default)]
    pub homepage: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub downloads: Option<i64>,
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

/// Create a new package
#[utoipa::path(
    post,
    path = "/packages",
    request_body = CreatePackageRequest,
    responses(
        (status = 201, description = "Package created", body = PackageResponse),
        (status = 400, description = "Bad request")
    )
)]
pub async fn create(
    State(state): State<SharedState>,
    Json(payload): Json<CreatePackageRequest>,
) -> Result<Json<packages::Model>, StatusCode> {
    // Check if package already exists
    let existing = packages::Entity::find()
        .filter(packages::Column::Name.eq(&payload.name))
        .one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    if let Some(pkg) = existing {
        return Ok(Json(pkg));
    }
    
    let pkg = packages::ActiveModel {
        id: sea_orm::NotSet,
        name: sea_orm::Set(payload.name),
        repository_url: sea_orm::Set(payload.repository_url),
        homepage: sea_orm::Set(payload.homepage),
        description: sea_orm::Set(payload.description),
        downloads: sea_orm::Set(payload.downloads),
        created_at: sea_orm::NotSet,
        updated_at: sea_orm::NotSet,
    };
    
    let result = packages::Entity::insert(pkg)
        .exec(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    // Fetch the created package
    let created = packages::Entity::find_by_id(result.last_insert_id)
        .one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    
    Ok(Json(created))
}

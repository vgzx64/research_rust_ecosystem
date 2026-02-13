//! Vulnerability handlers

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
};
use sea_orm::{EntityTrait, QueryFilter, ColumnTrait};
use serde::Deserialize;

use crate::db::SharedState;
use crate::models::{
    vulnerabilities, vulnerability_ids, fix_commits, file_changes, functions,
};

#[derive(Deserialize)]
pub struct ListQuery {
    pub limit: Option<u64>,
    pub offset: Option<u64>,
    pub package_name: Option<String>,
    pub severity_id: Option<i32>,
    pub type_id: Option<i32>,
}

#[derive(Deserialize)]
pub struct SearchQuery {
    pub id_type: String,
    pub id_value: String,
}

#[derive(serde::Serialize)]
pub struct VulnerabilityResponse {
    pub id: i32,
    pub package_name: String,
    pub severity_id: i32,
    pub type_id: i32,
    pub summary: Option<String>,
    pub details: Option<String>,
    pub published_at: Option<String>,
}

pub async fn list(
    State(state): State<SharedState>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Vec<VulnerabilityResponse>>, StatusCode> {
    let mut select = vulnerabilities::Entity::find();
    
    if let Some(ref pkg) = query.package_name {
        select = select.filter(vulnerabilities::Column::PackageName.eq(pkg));
    }
    if let Some(sev_id) = query.severity_id {
        select = select.filter(vulnerabilities::Column::SeverityId.eq(sev_id));
    }
    if let Some(t_id) = query.type_id {
        select = select.filter(vulnerabilities::Column::TypeId.eq(t_id));
    }
    
    let vulnerabilities = select.all(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let response: Vec<VulnerabilityResponse> = vulnerabilities.into_iter().map(|v| VulnerabilityResponse {
        id: v.id,
        package_name: v.package_name,
        severity_id: v.severity_id,
        type_id: v.type_id,
        summary: v.summary,
        details: v.details,
        published_at: v.published_at.map(|dt| dt.to_string()),
    }).collect();
    
    Ok(Json(response))
}

pub async fn get_by_id(
    State(state): State<SharedState>,
    Path(id): Path<i32>,
) -> Result<Json<VulnerabilityResponse>, StatusCode> {
    let vuln = vulnerabilities::Entity::find_by_id(id)
        .one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    
    Ok(Json(VulnerabilityResponse {
        id: vuln.id,
        package_name: vuln.package_name,
        severity_id: vuln.severity_id,
        type_id: vuln.type_id,
        summary: vuln.summary,
        details: vuln.details,
        published_at: vuln.published_at.map(|dt| dt.to_string()),
    }))
}

pub async fn search(
    State(state): State<SharedState>,
    Query(query): Query<SearchQuery>,
) -> Result<Json<VulnerabilityResponse>, StatusCode> {
    let vuln_id = vulnerability_ids::Entity::find()
        .filter(vulnerability_ids::Column::IdType.eq(&query.id_type))
        .filter(vulnerability_ids::Column::IdValue.eq(&query.id_value))
        .one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .map(|v| v.vulnerability_id)
        .ok_or(StatusCode::NOT_FOUND)?;
    
    let vuln = vulnerabilities::Entity::find_by_id(vuln_id)
        .one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    
    Ok(Json(VulnerabilityResponse {
        id: vuln.id,
        package_name: vuln.package_name,
        severity_id: vuln.severity_id,
        type_id: vuln.type_id,
        summary: vuln.summary,
        details: vuln.details,
        published_at: vuln.published_at.map(|dt| dt.to_string()),
    }))
}

pub async fn create(
    State(_state): State<SharedState>,
) -> Result<Json<String>, StatusCode> {
    Err(StatusCode::NOT_IMPLEMENTED)
}

pub async fn update(
    State(_state): State<SharedState>,
    Path(_id): Path<i32>,
) -> Result<Json<String>, StatusCode> {
    Err(StatusCode::NOT_IMPLEMENTED)
}

pub async fn delete(
    State(_state): State<SharedState>,
    Path(_id): Path<i32>,
) -> Result<StatusCode, StatusCode> {
    Err(StatusCode::NOT_IMPLEMENTED)
}

pub async fn get_commits(
    State(state): State<SharedState>,
    Path(id): Path<i32>,
) -> Result<Json<Vec<fix_commits::Model>>, StatusCode> {
    let commits = fix_commits::Entity::find()
        .filter(fix_commits::Column::VulnerabilityId.eq(id))
        .all(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    Ok(Json(commits))
}

pub async fn get_files(
    State(state): State<SharedState>,
    Path(id): Path<i32>,
) -> Result<Json<Vec<file_changes::Model>>, StatusCode> {
    let commits = fix_commits::Entity::find()
        .filter(fix_commits::Column::VulnerabilityId.eq(id))
        .all(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let commit_ids: Vec<i32> = commits.iter().map(|c| c.id).collect();
    
    if commit_ids.is_empty() {
        return Ok(Json(vec![]));
    }
    
    let files = file_changes::Entity::find()
        .filter(file_changes::Column::FixCommitId.is_in(commit_ids))
        .all(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    Ok(Json(files))
}

pub async fn get_functions(
    State(state): State<SharedState>,
    Path(id): Path<i32>,
) -> Result<Json<Vec<functions::Model>>, StatusCode> {
    let commits = fix_commits::Entity::find()
        .filter(fix_commits::Column::VulnerabilityId.eq(id))
        .all(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let commit_ids: Vec<i32> = commits.iter().map(|c| c.id).collect();
    
    if commit_ids.is_empty() {
        return Ok(Json(vec![]));
    }
    
    let funcs = functions::Entity::find()
        .filter(functions::Column::FixCommitId.is_in(commit_ids))
        .all(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    Ok(Json(funcs))
}

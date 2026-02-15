//! Vulnerability handlers

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
};
use sea_orm::{EntityTrait, QueryFilter, ColumnTrait, ActiveModelTrait};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::db::SharedState;
use crate::models::{
    vulnerabilities, vulnerability_ids, fix_commits, file_changes, functions,
    severity_levels, vulnerability_types, affected_versions, vulnerability_references,
};

#[derive(Deserialize, ToSchema)]
pub struct ListQuery {
    pub limit: Option<u64>,
    pub offset: Option<u64>,
    pub package_name: Option<String>,
    pub severity_id: Option<i32>,
    pub type_id: Option<i32>,
}

#[derive(Deserialize, ToSchema)]
pub struct SearchQuery {
    pub id_type: String,
    pub id_value: String,
}

#[derive(Serialize, ToSchema)]
pub struct VulnerabilityResponse {
    pub id: i32,
    pub package_name: String,
    pub severity_id: i32,
    pub type_id: i32,
    pub summary: Option<String>,
    pub details: Option<String>,
    pub published_at: Option<String>,
}

/// List vulnerabilities with optional filters
#[utoipa::path(
    get,
    path = "/vulnerabilities",
    responses(
        (status = 200, description = "List of vulnerabilities", body = [VulnerabilityResponse])
    )
)]
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

/// Create a new vulnerability (accepts IDs directly)
#[utoipa::path(
    post,
    path = "/vulnerabilities",
    request_body = VulnerabilityCreateRequestSimple,
    responses(
        (status = 201, description = "Vulnerability created", body = VulnerabilityResponse),
        (status = 400, description = "Bad request")
    )
)]
pub async fn create_simple(
    State(state): State<SharedState>,
    Json(payload): Json<VulnerabilityCreateRequestSimple>,
) -> Result<Json<VulnerabilityResponse>, StatusCode> {
    // Validate input
    if payload.package_id <= 0 {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Get package name
    let package = crate::models::packages::Entity::find_by_id(payload.package_id)
        .one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::BAD_REQUEST)?;

    // Check if vulnerability already exists for this package
    let existing_vuln = vulnerabilities::Entity::find()
        .filter(vulnerabilities::Column::PackageName.eq(&package.name))
        .one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let vulnerability = if let Some(existing) = existing_vuln {
        // Update existing vulnerability
        let type_id = payload.vulnerability_type_ids.first().copied().unwrap_or(1);
        
        let updated = vulnerabilities::ActiveModel {
            id: sea_orm::Set(existing.id),
            package_name: sea_orm::Set(existing.package_name),
            severity_id: sea_orm::Set(payload.severity_id),
            type_id: sea_orm::Set(type_id),
            summary: sea_orm::Set(payload.summary),
            details: sea_orm::Set(payload.details),
            published_at: sea_orm::Set(payload.published_at.and_then(|dt| dt.parse().ok())),
            created_at: sea_orm::Set(existing.created_at),
            updated_at: sea_orm::NotSet,
        };

        updated.update(&state.db)
            .await
            .map_err(|e| {
                eprintln!("Error updating vulnerability: {:?}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?
    } else {
        // Create new vulnerability
        let vulnerability = vulnerabilities::ActiveModel {
            id: sea_orm::NotSet,
            package_name: sea_orm::Set(package.name),
            severity_id: sea_orm::Set(payload.severity_id),
            type_id: sea_orm::Set(payload.vulnerability_type_ids.first().copied().unwrap_or(1)),
            summary: sea_orm::Set(payload.summary),
            details: sea_orm::Set(payload.details),
            published_at: sea_orm::Set(payload.published_at.and_then(|dt| dt.parse().ok())),
            created_at: sea_orm::NotSet,
            updated_at: sea_orm::NotSet,
        };

        vulnerability.insert(&state.db)
            .await
            .map_err(|e| {
                eprintln!("Error creating vulnerability: {:?}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?
    };

    Ok(Json(VulnerabilityResponse {
        id: vulnerability.id,
        package_name: vulnerability.package_name,
        severity_id: vulnerability.severity_id,
        type_id: vulnerability.type_id,
        summary: vulnerability.summary,
        details: vulnerability.details,
        published_at: vulnerability.published_at.map(|dt| dt.to_string()),
    }))
}

/// Simplified create request that accepts IDs directly
#[derive(Deserialize, ToSchema)]
pub struct VulnerabilityCreateRequestSimple {
    pub package_id: i32,
    pub severity_id: i32,
    pub vulnerability_type_ids: Vec<i32>,
    pub summary: Option<String>,
    pub details: Option<String>,
    pub published_at: Option<String>,
}

/// Get a vulnerability by ID
#[utoipa::path(
    get,
    path = "/vulnerabilities/{id}",
    responses(
        (status = 200, description = "Vulnerability found", body = VulnerabilityResponse),
        (status = 404, description = "Vulnerability not found")
    )
)]
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
    State(state): State<SharedState>,
    Json(payload): Json<VulnerabilityCreateRequest>,
) -> Result<Json<VulnerabilityResponse>, StatusCode> {
    // Validate input
    if payload.package_name.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Create or get severity level
    let severity_id = get_or_create_severity(&state.db, &payload.severity).await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Create or get vulnerability type
    let type_id = get_or_create_vulnerability_type(&state.db, &payload.vulnerability_type).await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Create vulnerability
    let vulnerability = vulnerabilities::ActiveModel {
        id: sea_orm::Set(0), // Auto-generated
        package_name: sea_orm::Set(payload.package_name.clone()),
        severity_id: sea_orm::Set(severity_id),
        type_id: sea_orm::Set(type_id),
        summary: sea_orm::Set(payload.summary),
        details: sea_orm::Set(payload.details),
        published_at: sea_orm::Set(payload.published_at.and_then(|dt| dt.parse().ok())),
        created_at: sea_orm::Set(None),
        updated_at: sea_orm::Set(None),
    };

    let vulnerability = vulnerability.insert(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Create vulnerability IDs
    for id in payload.vulnerability_ids {
        let vulnerability_id_model = vulnerability_ids::ActiveModel {
            id: sea_orm::Set(0), // Auto-generated
            vulnerability_id: sea_orm::Set(vulnerability.id),
            id_type: sea_orm::Set(id.id_type),
            id_value: sea_orm::Set(id.id_value),
        };
        
        vulnerability_id_model.insert(&state.db)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    // Create affected versions
    for version in payload.affected_versions {
        let affected_version = affected_versions::ActiveModel {
            id: sea_orm::Set(0), // Auto-generated
            vulnerability_id: sea_orm::Set(vulnerability.id),
            version_range: sea_orm::Set(version.version_range),
            introduced_version: sea_orm::Set(version.introduced_version),
            fixed_version: sea_orm::Set(version.fixed_version),
        };
        
        affected_version.insert(&state.db)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    // Create references
    for reference in payload.references {
        let reference_model = vulnerability_references::ActiveModel {
            id: sea_orm::Set(0), // Auto-generated
            vulnerability_id: sea_orm::Set(vulnerability.id),
            url: sea_orm::Set(reference.url),
        };
        
        reference_model.insert(&state.db)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    Ok(Json(VulnerabilityResponse {
        id: vulnerability.id,
        package_name: vulnerability.package_name,
        severity_id: vulnerability.severity_id,
        type_id: vulnerability.type_id,
        summary: vulnerability.summary,
        details: vulnerability.details,
        published_at: vulnerability.published_at.map(|dt| dt.to_string()),
    }))
}

#[derive(serde::Deserialize)]
pub struct VulnerabilityCreateRequest {
    pub package_name: String,
    pub severity: String, // e.g., "HIGH"
    pub vulnerability_type: String, // e.g., "Memory Management"
    pub summary: Option<String>,
    pub details: Option<String>,
    pub published_at: Option<String>,
    pub vulnerability_ids: Vec<VulnerabilityIdRequest>,
    pub affected_versions: Vec<AffectedVersionRequest>,
    pub references: Vec<ReferenceRequest>,
}

#[derive(serde::Deserialize)]
pub struct VulnerabilityIdRequest {
    pub id_type: String, // "GHSA", "CVE", "RUSTSEC"
    pub id_value: String,
}

#[derive(serde::Deserialize)]
pub struct AffectedVersionRequest {
    pub version_range: String,
    pub introduced_version: Option<String>,
    pub fixed_version: Option<String>,
}

#[derive(serde::Deserialize)]
pub struct ReferenceRequest {
    pub url: String,
}

async fn get_or_create_severity(db: &sea_orm::DatabaseConnection, severity: &str) -> Result<i32, sea_orm::DbErr> {
    use sea_orm::EntityTrait;
    
    // Try to find existing severity
    if let Some(severity_model) = severity_levels::Entity::find()
        .filter(severity_levels::Column::Level.eq(severity))
        .one(db)
        .await? 
    {
        return Ok(severity_model.id);
    }

    // Create new severity level
    let new_severity = severity_levels::ActiveModel {
        id: sea_orm::Set(0), // Auto-generated
        level: sea_orm::Set(severity.to_string()),
        min_cvss: sea_orm::Set(None),
        max_cvss: sea_orm::Set(None),
    };

    let result = new_severity.insert(db).await?;
    Ok(result.id)
}

async fn get_or_create_vulnerability_type(db: &sea_orm::DatabaseConnection, vuln_type: &str) -> Result<i32, sea_orm::DbErr> {
    use sea_orm::EntityTrait;
    
    // Try to find existing type
    if let Some(type_model) = vulnerability_types::Entity::find()
        .filter(vulnerability_types::Column::Name.eq(vuln_type))
        .one(db)
        .await? 
    {
        return Ok(type_model.id);
    }

    // Create new vulnerability type
    let new_type = vulnerability_types::ActiveModel {
        id: sea_orm::Set(0), // Auto-generated
        name: sea_orm::Set(vuln_type.to_string()),
        description: sea_orm::Set(None),
    };

    let result = new_type.insert(db).await?;
    Ok(result.id)
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

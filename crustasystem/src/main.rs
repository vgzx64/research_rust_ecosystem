//! Crustasystem - Vulnerability Database API

mod db;
mod models;
mod handlers;

use axum::{routing::get, Router};
use sea_orm::Database;
use std::net::SocketAddr;
use tower_http::cors::{Any, CorsLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

// OpenAPI documentation
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        handlers::health::health_check,
        handlers::severity_levels::list,
        handlers::vulnerability_types::list,
        handlers::packages::get_by_name,
        handlers::vulnerabilities::list,
        handlers::vulnerabilities::get_by_id,
    )
)]
struct ApiDoc;

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "crustasystem=debug,tower_http=debug".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting Crustasystem API");

    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite://CVEfixes.db".to_string());
    
    let db = Database::connect(&db_url)
        .await
        .expect("Failed to connect to database");
    
    tracing::info!("Connected to database: {}", db_url);

    let state = db::create_state(db);

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        // Health check
        .route("/health", get(handlers::health::health_check))
        // Severity levels
        .route("/severity-levels", get(handlers::severity_levels::list))
        // Vulnerability types
        .route("/vulnerability-types", get(handlers::vulnerability_types::list))
        // Packages
        .route("/packages/{name}", get(handlers::packages::get_by_name))
        // Vulnerabilities
        .route("/vulnerabilities", get(handlers::vulnerabilities::list))
        .route("/vulnerabilities/{id}", get(handlers::vulnerabilities::get_by_id))
        // Swagger
        .merge(SwaggerUi::new("/swagger-ui").url("/openapi.json", ApiDoc::openapi()))
        .layer(cors)
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    tracing::info!("Listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

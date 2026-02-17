//! Vulnerability data collection worker
//! 
//! This binary collects vulnerability data from local OSV dumps
//! and populates the database.
//!
//! Usage:
//!   cargo run --bin worker
//!   
//! Environment variables:
//!   DATABASE_URL - Database connection string (default: sqlite://crustasystem.db)
//!   DATA_DIR    - Path to data_collection directory (default: ../data_collection)

use std::path::PathBuf;

use sea_orm::Database;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// Import from the crate
use crustasystem::worker::collect_vulnerabilities;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting vulnerability collection worker");

    // Get database URL
    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite://crustasystem.db".to_string());
    
    tracing::info!("Connecting to database: {}", db_url);
    
    // Connect to database
    let db = Database::connect(&db_url).await?;
    
    tracing::info!("Connected to database");

    // Get data directory
    let data_dir = std::env::var("DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            // Default to ../data_collection relative to current directory
            std::env::current_dir()
                .expect("Failed to get current directory")
                .parent()
                    .expect("Failed to get parent directory")
                    .join("data_collection")
        });
    
    tracing::info!("Using data directory: {:?}", data_dir);

    // Run collection
    let result = collect_vulnerabilities(&db, &data_dir).await?;

    // Print summary
    println!("\n=== Collection Summary ===");
    println!("Total vulnerabilities: {}", result.total_vulnerabilities);
    println!("Inserted: {}", result.inserted_vulnerabilities);
    println!("Skipped (unmaintained): {}", result.skipped_unmaintained);
    println!("Skipped (malicious): {}", result.skipped_malicious);
    println!("Duplicates merged: {}", result.duplicates_merged);

    tracing::info!("Worker completed successfully");

    Ok(())
}
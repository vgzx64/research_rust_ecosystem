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
//!   LOG_DIR     - Directory for log files (default: logs)
//!   RUST_LOG    - Log level filter (default: info)

use std::path::PathBuf;

use sea_orm::Database;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

// Import from the crate
use crustasystem::worker::collect_vulnerabilities;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Get log directory from environment or use default
    let log_dir = std::env::var("LOG_DIR").unwrap_or_else(|_| "logs".to_string());
    
    // Create log directory if it doesn't exist
    std::fs::create_dir_all(&log_dir)?;

    // Rolling daily log file: logs/worker.YYYY-MM-DD
    let file_appender = tracing_appender::rolling::daily(&log_dir, "worker.log");
    let (non_blocking_file, _guard) = tracing_appender::non_blocking(file_appender);

    // Build env filter (RUST_LOG env var, default to debug for crustasystem, info for others)
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new("crustasystem=debug,info")
    });

    // Layer 1: Terminal output (with colors, compact format)
    let stdout_layer = fmt::layer()
        .with_target(true)
        .with_thread_ids(false)
        .with_ansi(true);

    // Layer 2: File output (no ANSI colors, full detail with file/line info)
    let file_layer = fmt::layer()
        .with_writer(non_blocking_file)
        .with_ansi(false)
        .with_target(true)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .with_level(true);

    // Initialize subscriber with both layers
    tracing_subscriber::registry()
        .with(env_filter)
        .with(stdout_layer)
        .with(file_layer)
        .init();

    tracing::info!("Starting vulnerability collection worker");
    tracing::info!("Log file: {}/worker.<date>", log_dir);

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
    tracing::info!("=== Collection Summary ===");
    tracing::info!("Total vulnerabilities processed: {}", result.total_vulnerabilities);
    tracing::info!("Inserted: {}", result.inserted_vulnerabilities);
    tracing::info!("Skipped (unmaintained): {}", result.skipped_unmaintained);
    tracing::info!("Skipped (malicious): {}", result.skipped_malicious);
    tracing::info!("Duplicates merged: {}", result.duplicates_merged);

    println!("\n=== Collection Summary ===");
    println!("Total vulnerabilities: {}", result.total_vulnerabilities);
    println!("Inserted: {}", result.inserted_vulnerabilities);
    println!("Skipped (unmaintained): {}", result.skipped_unmaintained);
    println!("Skipped (malicious): {}", result.skipped_malicious);
    println!("Duplicates merged: {}", result.duplicates_merged);

    tracing::info!("Worker completed successfully");

    Ok(())
}
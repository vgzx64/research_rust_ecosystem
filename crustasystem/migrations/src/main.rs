//! Migration runner binary

use sea_orm_migration::prelude::*;
use migrations::Migrator;

#[tokio::main]
async fn main() {
    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite://crustasystem.db?mode=rwc".to_string());
    
    println!("Connecting to database: {}", db_url);
    
    let db = sea_orm::Database::connect(&db_url)
        .await
        .expect("Failed to connect to database");
    
    println!("Running migrations...");
    Migrator::up(&db, None).await.expect("Failed to run migrations");
    
    println!("Migrations completed successfully!");
}

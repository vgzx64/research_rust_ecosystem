//! SeaORM Migration module
//! 
//! This module contains all database migrations for the crustasystem application.

pub use sea_orm_migration::prelude::*;

pub mod m20260215_171037_create_new_schema;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![Box::new(m20260215_171037_create_new_schema::Migration)]
    }
}

pub struct Migrator;

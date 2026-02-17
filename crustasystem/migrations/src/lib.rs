//! SeaORM Migration module
//! 
//! This module contains all database migrations for the crustasystem application.

pub use sea_orm_migration::prelude::*;

pub mod m20260215_171037_create_new_schema;
pub mod m20260217_174900_add_constraints_and_indexes;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20260215_171037_create_new_schema::Migration),
            Box::new(m20260217_174900_add_constraints_and_indexes::Migration),
        ]
    }
}

pub struct Migrator;

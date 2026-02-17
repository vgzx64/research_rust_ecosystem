//! Migration: Seed initial data
//! 
//! This migration inserts seed data for:
//! - severity_levels: LOW, MEDIUM, HIGH, CRITICAL
//! - vulnerability_types: 17 categories from RQ1 analysis

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Insert severity levels
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                INSERT INTO severity_level (level, min_cvss, max_cvss) VALUES
                    ('LOW', 0.0, 3.9),
                    ('MEDIUM', 4.0, 6.9),
                    ('HIGH', 7.0, 8.9),
                    ('CRITICAL', 9.0, 10.0);
                "#,
            )
            .await?;

        // Insert vulnerability types (from RQ1 analysis)
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                INSERT INTO vulnerability_type (name, description) VALUES
                    ('Memory Management', 'Issues related to memory allocation, deallocation, and lifecycle management'),
                    ('Memory Access', 'Invalid or unsafe memory access patterns'),
                    ('Synchronization', 'Race conditions, deadlocks, and thread safety issues'),
                    ('Tainted Input', 'Improper handling of untrusted input data'),
                    ('Resource Management', 'Improper management of system resources'),
                    ('Exception Management', 'Improper handling of error conditions and exceptions'),
                    ('Cryptography', 'Weak or incorrect cryptographic implementations'),
                    ('Other', 'Miscellaneous vulnerability types'),
                    ('Risky Values', 'Dangerous or unexpected values in computations'),
                    ('Path Resolution', 'Issues with file path handling and resolution'),
                    ('Information Leak', 'Exposure of sensitive information'),
                    ('Privilege', 'Privilege escalation or improper permission handling'),
                    ('Predictability', 'Predictable or guessable values in security contexts'),
                    ('Authentication', 'Authentication bypass or weakness'),
                    ('API', 'API misuse or contract violations'),
                    ('Access Control', 'Improper access control mechanisms'),
                    ('Failure to Release Memory', 'Memory leaks and resource leaks');
                "#,
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Clear seed data (order matters due to foreign keys)
        manager
            .get_connection()
            .execute_unprepared("DELETE FROM vulnerability_type;")
            .await?;
        
        manager
            .get_connection()
            .execute_unprepared("DELETE FROM severity_level;")
            .await?;

        Ok(())
    }
}
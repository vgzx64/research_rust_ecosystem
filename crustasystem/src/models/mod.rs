//! Database models for Crustasystem
//! 
//! This module contains SeaORM entity definitions for the vulnerability database.
//! Models are organized following the 3NF schema design.

pub mod severity_levels;
pub mod vulnerability_types;
pub mod vulnerabilities;
pub mod vulnerability_ids;
pub mod affected_versions;
pub mod vulnerability_references;
pub mod packages;
pub mod fix_commits;
pub mod file_changes;
pub mod diff_lines;
pub mod functions;
pub mod unsafe_blocks;
pub mod vulnerability_statistics;

// Re-export all models for easy access
pub use severity_levels::Entity as SeverityLevelEntity;
pub use vulnerability_types::Entity as VulnerabilityTypeEntity;
pub use vulnerabilities::Entity as VulnerabilityEntity;
pub use vulnerability_ids::Entity as VulnerabilityIdEntity;
pub use affected_versions::Entity as AffectedVersionEntity;
pub use vulnerability_references::Entity as VulnerabilityReferenceEntity;
pub use packages::Entity as PackageEntity;
pub use fix_commits::Entity as FixCommitEntity;
pub use file_changes::Entity as FileChangeEntity;
pub use diff_lines::Entity as DiffLineEntity;
pub use functions::Entity as FunctionEntity;
pub use unsafe_blocks::Entity as UnsafeBlockEntity;
pub use vulnerability_statistics::Entity as VulnerabilityStatisticEntity;

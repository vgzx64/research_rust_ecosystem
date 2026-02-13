//! Affected versions model
//! 
//! Tracks which versions of a package are affected by a vulnerability

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "affected_versions")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = true)]
    pub id: i32,
    pub vulnerability_id: i32,  // FK to vulnerabilities
    pub version_range: String,   // e.g., '>=1.0.0,<2.0.0'
    pub introduced_version: Option<String>,
    pub fixed_version: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::vulnerabilities::Entity",
        from = "Column::VulnerabilityId",
        to = "super::vulnerabilities::Column::Id"
    )]
    Vulnerability,
}

impl Related<super::vulnerabilities::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Vulnerability.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

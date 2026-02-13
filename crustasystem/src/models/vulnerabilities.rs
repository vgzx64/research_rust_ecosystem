//! Vulnerabilities model
//! 
//! Central table for vulnerability records

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "vulnerabilities")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = true)]
    pub id: i32,
    pub package_name: String,
    pub severity_id: i32,          // FK to severity_levels
    pub type_id: i32,              // FK to vulnerability_types
    pub summary: Option<String>,
    pub details: Option<String>,
    pub published_at: Option<DateTime>,
    pub created_at: Option<DateTime>,
    pub updated_at: Option<DateTime>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::severity_levels::Entity",
        from = "Column::SeverityId",
        to = "super::severity_levels::Column::Id"
    )]
    SeverityLevel,
    #[sea_orm(
        belongs_to = "super::vulnerability_types::Entity",
        from = "Column::TypeId",
        to = "super::vulnerability_types::Column::Id"
    )]
    VulnerabilityType,
}

impl Related<super::severity_levels::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::SeverityLevel.def()
    }
}

impl Related<super::vulnerability_types::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::VulnerabilityType.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

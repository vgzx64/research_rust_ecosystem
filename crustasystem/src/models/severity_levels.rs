//! Severity levels model
//! 
//! Seeded table for CVSS severity levels: LOW, MEDIUM, HIGH, CRITICAL

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "severity_levels")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = true)]
    pub id: i32,
    #[sea_orm(column_type = "Text", unique)]
    pub level: String,  // 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    pub min_cvss: Option<f64>,
    pub max_cvss: Option<f64>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

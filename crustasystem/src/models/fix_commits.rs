//! Fix commits model
//! 
//! Tracks fix commits for vulnerabilities

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "fix_commits")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = true)]
    pub id: i32,
    pub vulnerability_id: i32,  // FK to vulnerabilities
    pub commit_hash: String,
    pub repository_url: String,
    pub commit_message: Option<String>,
    pub committed_at: Option<DateTime>,
    pub num_files_changed: Option<i32>,
    pub num_additions: Option<i32>,
    pub num_deletions: Option<i32>,
    pub created_at: Option<DateTime>,
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

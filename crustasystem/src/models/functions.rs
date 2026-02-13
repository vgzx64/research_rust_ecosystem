//! Functions model
//! 
//! Extracted function information from compiler analysis

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "functions")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = true)]
    pub id: i32,
    pub fix_commit_id: i32,  // FK to fix_commits
    pub version: String,  // 'vulnerable' or 'fixed'
    pub file_path: String,
    pub function_name: Option<String>,
    pub line_start: Option<i32>,
    pub line_end: Option<i32>,
    pub is_unsafe: Option<bool>,
    pub code_snippet: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::fix_commits::Entity",
        from = "Column::FixCommitId",
        to = "super::fix_commits::Column::Id"
    )]
    FixCommit,
}

impl Related<super::fix_commits::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::FixCommit.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

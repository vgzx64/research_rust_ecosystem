//! File changes model
//! 
//! Tracks files modified in fix commits

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "file_changes")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = true)]
    pub id: i32,
    pub fix_commit_id: i32,  // FK to fix_commits
    pub file_path: String,
    pub old_path: Option<String>,  // For renamed files
    pub change_type: String,  // 'added', 'modified', 'deleted', 'renamed'
    pub diff: Option<String>,
    pub num_additions: Option<i32>,
    pub num_deletions: Option<i32>,
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

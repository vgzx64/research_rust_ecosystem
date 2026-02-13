//! Unsafe blocks model
//! 
//! Unsafe blocks within functions

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "unsafe_blocks")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = true)]
    pub id: i32,
    pub function_id: Option<i32>,  // FK to functions
    pub fix_commit_id: i32,  // FK to fix_commits
    pub version: String,  // 'vulnerable' or 'fixed'
    pub block_type: Option<String>,  // 'unsafe block', 'unsafe fn', 'unsafe trait'
    pub line_start: Option<i32>,
    pub line_end: Option<i32>,
    pub code_snippet: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::functions::Entity",
        from = "Column::FunctionId",
        to = "super::functions::Column::Id"
    )]
    Function,
    #[sea_orm(
        belongs_to = "super::fix_commits::Entity",
        from = "Column::FixCommitId",
        to = "super::fix_commits::Column::Id"
    )]
    FixCommit,
}

impl Related<super::functions::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Function.def()
    }
}

impl Related<super::fix_commits::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::FixCommit.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

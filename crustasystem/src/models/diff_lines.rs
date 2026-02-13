//! Diff lines model
//! 
//! Normalized diff lines - in 3NF

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "diff_lines")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = true)]
    pub id: i32,
    pub file_change_id: i32,  // FK to file_changes
    pub line_number: i32,
    pub content: String,
    pub line_type: String,  // 'added' or 'deleted'
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::file_changes::Entity",
        from = "Column::FileChangeId",
        to = "super::file_changes::Column::Id"
    )]
    FileChange,
}

impl Related<super::file_changes::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::FileChange.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

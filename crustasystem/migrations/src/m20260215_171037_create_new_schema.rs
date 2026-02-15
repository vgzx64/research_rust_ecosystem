use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create severity_levels table
        manager
            .create_table(
                Table::create()
                    .table(SeverityLevel::Table)
                    .if_not_exists()
                    .col(pk_auto(SeverityLevel::Id))
                    .col(string(SeverityLevel::Level).unique_key())
                    .col(float(SeverityLevel::MinCvss))
                    .col(float(SeverityLevel::MaxCvss))
                    .to_owned(),
            )
            .await?;

        // Create vulnerability_types table
        manager
            .create_table(
                Table::create()
                    .table(VulnerabilityType::Table)
                    .if_not_exists()
                    .col(pk_auto(VulnerabilityType::Id))
                    .col(string(VulnerabilityType::Name).unique_key())
                    .col(string(VulnerabilityType::Description))
                    .to_owned(),
            )
            .await?;

        // Create packages table
        manager
            .create_table(
                Table::create()
                    .table(Package::Table)
                    .if_not_exists()
                    .col(pk_auto(Package::Id))
                    .col(string(Package::Name).unique_key())
                    .col(string(Package::RepositoryUrl).nullable())
                    .col(string(Package::Homepage).nullable())
                    .col(string(Package::Description).nullable())
                    .col(integer(Package::Downloads))
                    .col(date_time(Package::CreatedAt))
                    .col(date_time(Package::UpdatedAt))
                    .to_owned(),
            )
            .await?;

        // Create vulnerabilities table
        manager
            .create_table(
                Table::create()
                    .table(Vulnerability::Table)
                    .if_not_exists()
                    .col(pk_auto(Vulnerability::Id))
                    .col(string(Vulnerability::PackageName))
                    .col(integer(Vulnerability::SeverityId))
                    .col(integer(Vulnerability::TypeId))
                    .col(string(Vulnerability::Summary).nullable())
                    .col(string(Vulnerability::Details).nullable())
                    .col(date_time(Vulnerability::PublishedAt))
                    .col(date_time(Vulnerability::CreatedAt))
                    .col(date_time(Vulnerability::UpdatedAt))
                    .foreign_key(
                        ForeignKey::create()
                            .from(Vulnerability::Table, Vulnerability::SeverityId)
                            .to(SeverityLevel::Table, SeverityLevel::Id),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(Vulnerability::Table, Vulnerability::TypeId)
                            .to(VulnerabilityType::Table, VulnerabilityType::Id),
                    )
                    .to_owned(),
            )
            .await?;

        // Create vulnerability_ids table
        manager
            .create_table(
                Table::create()
                    .table(VulnerabilityId::Table)
                    .if_not_exists()
                    .col(pk_auto(VulnerabilityId::Id))
                    .col(integer(VulnerabilityId::VulnerabilityId))
                    .col(string(VulnerabilityId::IdType))
                    .col(string(VulnerabilityId::IdValue))
                    .foreign_key(
                        ForeignKey::create()
                            .from(VulnerabilityId::Table, VulnerabilityId::VulnerabilityId)
                            .to(Vulnerability::Table, Vulnerability::Id),
                    )
                    .to_owned(),
            )
            .await?;

        // Create affected_versions table
        manager
            .create_table(
                Table::create()
                    .table(AffectedVersion::Table)
                    .if_not_exists()
                    .col(pk_auto(AffectedVersion::Id))
                    .col(integer(AffectedVersion::VulnerabilityId))
                    .col(string(AffectedVersion::VersionRange))
                    .col(string(AffectedVersion::IntroducedVersion))
                    .col(string(AffectedVersion::FixedVersion))
                    .foreign_key(
                        ForeignKey::create()
                            .from(AffectedVersion::Table, AffectedVersion::VulnerabilityId)
                            .to(Vulnerability::Table, Vulnerability::Id),
                    )
                    .to_owned(),
            )
            .await?;

        // Create vulnerability_references table
        manager
            .create_table(
                Table::create()
                    .table(VulnerabilityReference::Table)
                    .if_not_exists()
                    .col(pk_auto(VulnerabilityReference::Id))
                    .col(integer(VulnerabilityReference::VulnerabilityId))
                    .col(string(VulnerabilityReference::Url))
                    .foreign_key(
                        ForeignKey::create()
                            .from(VulnerabilityReference::Table, VulnerabilityReference::VulnerabilityId)
                            .to(Vulnerability::Table, Vulnerability::Id),
                    )
                    .to_owned(),
            )
            .await?;

        // Create fix_commits table
        manager
            .create_table(
                Table::create()
                    .table(FixCommit::Table)
                    .if_not_exists()
                    .col(pk_auto(FixCommit::Id))
                    .col(integer(FixCommit::VulnerabilityId))
                    .col(string(FixCommit::CommitHash))
                    .col(string(FixCommit::RepositoryUrl))
                    .col(string(FixCommit::CommitMessage))
                    .col(date_time(FixCommit::CommittedAt))
                    .col(integer(FixCommit::NumFilesChanged))
                    .col(integer(FixCommit::NumAdditions))
                    .col(integer(FixCommit::NumDeletions))
                    .col(date_time(FixCommit::CreatedAt))
                    .foreign_key(
                        ForeignKey::create()
                            .from(FixCommit::Table, FixCommit::VulnerabilityId)
                            .to(Vulnerability::Table, Vulnerability::Id),
                    )
                    .to_owned(),
            )
            .await?;

        // Create file_changes table
        manager
            .create_table(
                Table::create()
                    .table(FileChange::Table)
                    .if_not_exists()
                    .col(pk_auto(FileChange::Id))
                    .col(integer(FileChange::FixCommitId))
                    .col(string(FileChange::FilePath))
                    .col(string(FileChange::OldPath))
                    .col(string(FileChange::ChangeType))
                    .col(text(FileChange::Diff))
                    .col(integer(FileChange::NumAdditions))
                    .col(integer(FileChange::NumDeletions))
                    .foreign_key(
                        ForeignKey::create()
                            .from(FileChange::Table, FileChange::FixCommitId)
                            .to(FixCommit::Table, FixCommit::Id),
                    )
                    .to_owned(),
            )
            .await?;

        // Create diff_lines table
        manager
            .create_table(
                Table::create()
                    .table(DiffLine::Table)
                    .if_not_exists()
                    .col(pk_auto(DiffLine::Id))
                    .col(integer(DiffLine::FileChangeId))
                    .col(integer(DiffLine::LineNumber))
                    .col(string(DiffLine::Content))
                    .col(string(DiffLine::LineType))
                    .foreign_key(
                        ForeignKey::create()
                            .from(DiffLine::Table, DiffLine::FileChangeId)
                            .to(FileChange::Table, FileChange::Id),
                    )
                    .to_owned(),
            )
            .await?;

        // Create functions table
        manager
            .create_table(
                Table::create()
                    .table(Function::Table)
                    .if_not_exists()
                    .col(pk_auto(Function::Id))
                    .col(integer(Function::FixCommitId))
                    .col(string(Function::Version))
                    .col(string(Function::FilePath))
                    .col(string(Function::FunctionName))
                    .col(integer(Function::LineStart))
                    .col(integer(Function::LineEnd))
                    .col(boolean(Function::IsUnsafe))
                    .col(text(Function::CodeSnippet))
                    .foreign_key(
                        ForeignKey::create()
                            .from(Function::Table, Function::FixCommitId)
                            .to(FixCommit::Table, FixCommit::Id),
                    )
                    .to_owned(),
            )
            .await?;

        // Create unsafe_blocks table
        manager
            .create_table(
                Table::create()
                    .table(UnsafeBlock::Table)
                    .if_not_exists()
                    .col(pk_auto(UnsafeBlock::Id))
                    .col(integer(UnsafeBlock::FunctionId))
                    .col(integer(UnsafeBlock::FixCommitId))
                    .col(string(UnsafeBlock::Version))
                    .col(string(UnsafeBlock::BlockType))
                    .col(integer(UnsafeBlock::LineStart))
                    .col(integer(UnsafeBlock::LineEnd))
                    .col(text(UnsafeBlock::CodeSnippet))
                    .foreign_key(
                        ForeignKey::create()
                            .from(UnsafeBlock::Table, UnsafeBlock::FunctionId)
                            .to(Function::Table, Function::Id),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(UnsafeBlock::Table, UnsafeBlock::FixCommitId)
                            .to(FixCommit::Table, FixCommit::Id),
                    )
                    .to_owned(),
            )
            .await?;

        // Create vulnerability_statistics table
        manager
            .create_table(
                Table::create()
                    .table(VulnerabilityStatistic::Table)
                    .if_not_exists()
                    .col(integer(VulnerabilityStatistic::VulnerabilityId).primary_key())
                    .col(integer(VulnerabilityStatistic::VulnSafeFunctions))
                    .col(integer(VulnerabilityStatistic::VulnUnsafeFunctions))
                    .col(integer(VulnerabilityStatistic::VulnUnsafeBlocks))
                    .col(integer(VulnerabilityStatistic::FixSafeFunctions))
                    .col(integer(VulnerabilityStatistic::FixUnsafeFunctions))
                    .col(integer(VulnerabilityStatistic::FixUnsafeBlocks))
                    .col(integer(VulnerabilityStatistic::FilesChanged))
                    .col(integer(VulnerabilityStatistic::TotalAdditions))
                    .col(integer(VulnerabilityStatistic::TotalDeletions))
                    .foreign_key(
                        ForeignKey::create()
                            .from(VulnerabilityStatistic::Table, VulnerabilityStatistic::VulnerabilityId)
                            .to(Vulnerability::Table, Vulnerability::Id),
                    )
                    .to_owned(),
            )
            .await?;

        // Note: Seed data will be inserted separately after migrations
        // using SQL INSERT statements to avoid StatementBuilder issues
        
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Drop tables in reverse order (due to foreign key dependencies)
        manager
            .drop_table(Table::drop().table(VulnerabilityStatistic::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(UnsafeBlock::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Function::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(DiffLine::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(FileChange::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(FixCommit::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(VulnerabilityReference::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(AffectedVersion::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(VulnerabilityId::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Vulnerability::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Package::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(VulnerabilityType::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(SeverityLevel::Table).to_owned())
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum SeverityLevel {
    Table,
    Id,
    Level,
    MinCvss,
    MaxCvss,
}

#[derive(DeriveIden)]
enum VulnerabilityType {
    Table,
    Id,
    Name,
    Description,
}

#[derive(DeriveIden)]
enum Package {
    Table,
    Id,
    Name,
    RepositoryUrl,
    Homepage,
    Description,
    Downloads,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum Vulnerability {
    Table,
    Id,
    PackageName,
    SeverityId,
    TypeId,
    Summary,
    Details,
    PublishedAt,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum VulnerabilityId {
    Table,
    Id,
    VulnerabilityId,
    IdType,
    IdValue,
}

#[derive(DeriveIden)]
enum AffectedVersion {
    Table,
    Id,
    VulnerabilityId,
    VersionRange,
    IntroducedVersion,
    FixedVersion,
}

#[derive(DeriveIden)]
enum VulnerabilityReference {
    Table,
    Id,
    VulnerabilityId,
    Url,
}

#[derive(DeriveIden)]
enum FixCommit {
    Table,
    Id,
    VulnerabilityId,
    CommitHash,
    RepositoryUrl,
    CommitMessage,
    CommittedAt,
    NumFilesChanged,
    NumAdditions,
    NumDeletions,
    CreatedAt,
}

#[derive(DeriveIden)]
enum FileChange {
    Table,
    Id,
    FixCommitId,
    FilePath,
    OldPath,
    ChangeType,
    Diff,
    NumAdditions,
    NumDeletions,
}

#[derive(DeriveIden)]
enum DiffLine {
    Table,
    Id,
    FileChangeId,
    LineNumber,
    Content,
    LineType,
}

#[derive(DeriveIden)]
enum Function {
    Table,
    Id,
    FixCommitId,
    Version,
    FilePath,
    FunctionName,
    LineStart,
    LineEnd,
    IsUnsafe,
    CodeSnippet,
}

#[derive(DeriveIden)]
enum UnsafeBlock {
    Table,
    Id,
    FunctionId,
    FixCommitId,
    Version,
    BlockType,
    LineStart,
    LineEnd,
    CodeSnippet,
}

#[derive(DeriveIden)]
enum VulnerabilityStatistic {
    Table,
    VulnerabilityId,
    VulnSafeFunctions,
    VulnUnsafeFunctions,
    VulnUnsafeBlocks,
    FixSafeFunctions,
    FixUnsafeFunctions,
    FixUnsafeBlocks,
    FilesChanged,
    TotalAdditions,
    TotalDeletions,
}

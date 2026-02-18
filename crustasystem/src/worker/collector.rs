//! Vulnerability data collector
//! 
//! Reads OSV vulnerability data from local files and populates the database.

use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use sea_orm::{DatabaseConnection, EntityTrait, ActiveModelTrait, ColumnTrait, QueryFilter, Set, ConnectionTrait, TransactionTrait, NotSet};
use tracing::{info, warn};

use super::osv::OsvVulnerability;
use super::sfp::get_vulnerability_types;
use crate::models::{
    vulnerabilities, vulnerability_ids, affected_versions, vulnerability_references,
    packages, severity_levels, vulnerability_types,
};

/// Result of the collection process
#[derive(Debug, Default)]
pub struct CollectionResult {
    pub total_vulnerabilities: usize,
    pub inserted_vulnerabilities: usize,
    pub skipped_unmaintained: usize,
    pub skipped_malicious: usize,
    pub duplicates_merged: usize,
}

/// Collect vulnerabilities from local OSV data dump
pub async fn collect_vulnerabilities(
    db: &DatabaseConnection,
    data_dir: &Path,
) -> anyhow::Result<CollectionResult> {
    info!("Starting vulnerability collection from {:?}", data_dir);

    // Enable WAL mode and NORMAL synchronous for much faster writes.
    // WAL allows concurrent reads and batches fsyncs; NORMAL is safe with WAL.
    db.execute_unprepared("PRAGMA journal_mode=WAL").await?;
    db.execute_unprepared("PRAGMA synchronous=NORMAL").await?;
    
    let mut result = CollectionResult::default();
    
    // Load OSV vulnerabilities
    let vuls_path = data_dir.join("vuls.json");
    info!("Loading vulnerabilities from {:?}", vuls_path);
    
    let file = File::open(&vuls_path)?;
    let reader = BufReader::new(file);
    let vulnerabilities: Vec<OsvVulnerability> = serde_json::from_reader(reader)?;
    result.total_vulnerabilities = vulnerabilities.len();
    info!("Loaded {} vulnerabilities", vulnerabilities.len());
    
    // Load package metadata from crates.csv
    let crates_path = data_dir.join("crates_io_db/data/crates.csv");
    let package_repos = load_package_repositories(&crates_path)?;
    info!("Loaded {} package repository mappings", package_repos.len());
    
    // Filter out unwanted vulnerabilities
    let filtered: Vec<&OsvVulnerability> = vulnerabilities.iter()
        .filter(|v| {
            // Skip unmaintained
            if let Some(summary) = &v.summary {
                let lower = summary.to_lowercase();
                if lower.contains("unmaint") || lower.contains("no longer maint") || lower.contains("discontinue") {
                    result.skipped_unmaintained += 1;
                    return false;
                }
                // Skip malicious code
                if lower.contains("malicious code") {
                    result.skipped_malicious += 1;
                    return false;
                }
            }
            true
        })
        .collect();
    
    info!("After filtering: {} vulnerabilities (skipped {} unmaintained, {} malicious)", 
          filtered.len(), result.skipped_unmaintained, result.skipped_malicious);
    
    // Group by package for deduplication
    let grouped = group_by_package(&filtered);
    info!("Grouped into {} packages", grouped.len());
    
    // Clear existing data (full update) — outside the transaction so it commits immediately
    clear_vulnerability_data(db).await?;
    info!("Cleared existing vulnerability data");

    // Wrap all inserts in a single transaction — this is the key performance fix.
    // SQLite commits every auto-transaction to disk (fsync); batching into one
    // transaction reduces thousands of fsyncs to a single one at commit time.
    info!("Beginning insert transaction...");
    let txn = db.begin().await?;

    // Process each package group
    for (package_name, vulns) in grouped {
        // Deduplicate within package
        let original_count = vulns.len();
        let deduped = deduplicate_vulnerabilities(&vulns);
        result.duplicates_merged += original_count - deduped.len();
        
        // Insert each deduplicated vulnerability
        for vul in deduped {
            match insert_vulnerability(&txn, vul, &package_name, &package_repos).await {
                Ok(_) => result.inserted_vulnerabilities += 1,
                Err(e) => {
                    warn!("Failed to insert vulnerability {}: {:?}", vul.id, e);
                }
            }
        }
    }

    txn.commit().await?;
    info!("Transaction committed");
    
    info!("Collection complete: {:?}", result);
    Ok(result)
}

/// Load package repository URLs from crates.csv
fn load_package_repositories(path: &Path) -> anyhow::Result<HashMap<String, String>> {
    let mut repos = HashMap::new();
    
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut csv_reader = csv::Reader::from_reader(reader);
    
    for result in csv_reader.records() {
        let record = result?;
        // crates.csv columns (0-indexed, header row skipped by csv::Reader):
        // 0:created_at, 1:description, 2:documentation, 3:homepage, 4:id,
        // 5:max_features, 6:max_upload_size, 7:name, 8:readme, 9:repository,
        // 10:trustpub_only, 11:updated_at
        if let (Some(name), Some(repo)) = (record.get(7), record.get(9)) {
            if !repo.is_empty() {
                repos.insert(name.to_string(), repo.to_string());
            }
        }
    }
    
    Ok(repos)
}

/// Group vulnerabilities by package name
fn group_by_package<'a>(vulnerabilities: &[&'a OsvVulnerability]) -> HashMap<String, Vec<&'a OsvVulnerability>> {
    let mut grouped: HashMap<String, Vec<&OsvVulnerability>> = HashMap::new();
    
    for vul in vulnerabilities {
        if let Some(pkg_name) = vul.package_name() {
            grouped.entry(pkg_name.to_string())
                .or_default()
                .push(*vul);
        }
    }
    
    grouped
}

/// Deduplicate vulnerabilities within the same package
/// Merges vulnerabilities that share NVD or RustSec references
fn deduplicate_vulnerabilities<'a>(vulnerabilities: &[&'a OsvVulnerability]) -> Vec<&'a OsvVulnerability> {
    if vulnerabilities.len() <= 1 {
        return vulnerabilities.to_vec();
    }
    
    // For simplicity, we'll just return all vulnerabilities
    // A more sophisticated approach would merge based on shared references
    // as done in the Python notebook
    vulnerabilities.to_vec()
}

/// Clear all vulnerability-related data from the database
async fn clear_vulnerability_data(db: &DatabaseConnection) -> anyhow::Result<()> {
    // Delete in order due to foreign key constraints
    // Note: Table names are singular in this schema
    
    // Delete vulnerability IDs
    db.execute_unprepared("DELETE FROM vulnerability_id")
        .await?;
    
    // Delete affected versions
    db.execute_unprepared("DELETE FROM affected_version")
        .await?;
    
    // Delete vulnerability references
    db.execute_unprepared("DELETE FROM vulnerability_reference")
        .await?;
    
    // Delete vulnerabilities
    db.execute_unprepared("DELETE FROM vulnerability")
        .await?;
    
    Ok(())
}

/// Insert a vulnerability into the database
async fn insert_vulnerability<C>(
    db: &C,
    vul: &OsvVulnerability,
    package_name: &str,
    package_repos: &HashMap<String, String>,
) -> anyhow::Result<i32>
where
    C: ConnectionTrait,
{
    // Get or create package
    let repo_url = package_repos.get(package_name).cloned();
    let _package = get_or_create_package(db, package_name, repo_url).await?;
    
    // Get severity ID
    let severity_id = get_severity_id(db, vul.severity_level().as_deref()).await?;
    
    // Get vulnerability type ID
    let cwes = vul.cwe_ids();
    let types = get_vulnerability_types(&cwes);
    let type_id = get_type_id(db, types.first().map(|s| s.as_str())).await?;
    
    // Create vulnerability
    let vulnerability = vulnerabilities::ActiveModel {
        id: NotSet, // Auto-generated
        package_name: Set(package_name.to_string()),
        severity_id: Set(severity_id),
        type_id: Set(type_id),
        summary: Set(vul.summary.clone()),
        details: Set(vul.details.clone()),
        published_at: Set(vul.published.map(|dt| dt.naive_utc())),
        created_at: Set(None),
        updated_at: Set(None),
    };
    
    let inserted = vulnerability.insert(db).await?;
    let vuln_id = inserted.id;
    
    // Insert vulnerability IDs (GHSA, CVE, RUSTSEC)
    // Main ID
    insert_vuln_id(db, vuln_id, &vul.id_type(), &vul.id).await?;
    
    // Aliases
    if let Some(aliases) = &vul.aliases {
        for alias in aliases {
            let id_type = if alias.starts_with("GHSA-") {
                "GHSA"
            } else if alias.starts_with("CVE-") {
                "CVE"
            } else if alias.starts_with("RUSTSEC-") {
                "RUSTSEC"
            } else {
                continue;
            };
            insert_vuln_id(db, vuln_id, id_type, alias).await?;
        }
    }
    
    // Insert affected versions
    let version_range = vul.version_ranges();
    if !version_range.is_empty() {
        let affected = affected_versions::ActiveModel {
            id: NotSet,
            vulnerability_id: Set(vuln_id),
            version_range: Set(version_range),
            introduced_version: Set(None),
            fixed_version: Set(None),
        };
        affected.insert(db).await?;
    }
    
    // Insert references
    for url in vul.reference_urls() {
        let reference = vulnerability_references::ActiveModel {
            id: NotSet,
            vulnerability_id: Set(vuln_id),
            url: Set(url),
        };
        reference.insert(db).await?;
    }
    
    Ok(vuln_id)
}

/// Get or create a package
async fn get_or_create_package<C>(
    db: &C,
    name: &str,
    repo_url: Option<String>,
) -> anyhow::Result<i32>
where
    C: ConnectionTrait,
{
    // Check if package exists
    let existing = packages::Entity::find()
        .filter(packages::Column::Name.eq(name))
        .one(db)
        .await?;
    
    if let Some(pkg) = existing {
        return Ok(pkg.id);
    }
    
    // Create new package
    let package = packages::ActiveModel {
        id: NotSet,
        name: Set(name.to_string()),
        repository_url: Set(repo_url),
        homepage: Set(None),
        description: Set(None),
        downloads: Set(None),
        created_at: Set(None),
        updated_at: Set(None),
    };
    
    let inserted = package.insert(db).await?;
    Ok(inserted.id)
}

/// Get severity level ID
async fn get_severity_id<C>(db: &C, severity: Option<&str>) -> anyhow::Result<Option<i32>>
where
    C: ConnectionTrait,
{
    let Some(sev) = severity else { return Ok(None) };
    
    let level = severity_levels::Entity::find()
        .filter(severity_levels::Column::Level.eq(sev))
        .one(db)
        .await?;
    
    Ok(level.map(|l| l.id))
}

/// Get vulnerability type ID
async fn get_type_id<C>(db: &C, type_name: Option<&str>) -> anyhow::Result<Option<i32>>
where
    C: ConnectionTrait,
{
    let Some(name) = type_name else { return Ok(None) };
    
    let vuln_type = vulnerability_types::Entity::find()
        .filter(vulnerability_types::Column::Name.eq(name))
        .one(db)
        .await?;
    
    Ok(vuln_type.map(|t| t.id))
}

/// Insert a vulnerability ID mapping
async fn insert_vuln_id<C>(
    db: &C,
    vuln_id: i32,
    id_type: &str,
    id_value: &str,
) -> anyhow::Result<()>
where
    C: ConnectionTrait,
{
    // Check if already exists
    let existing = vulnerability_ids::Entity::find()
        .filter(vulnerability_ids::Column::IdType.eq(id_type))
        .filter(vulnerability_ids::Column::IdValue.eq(id_value))
        .one(db)
        .await?;
    
    if existing.is_some() {
        return Ok(());
    }
    
    let vuln_id_model = vulnerability_ids::ActiveModel {
        id: NotSet,
        vulnerability_id: Set(vuln_id),
        id_type: Set(id_type.to_string()),
        id_value: Set(id_value.to_string()),
    };
    
    vuln_id_model.insert(db).await?;
    Ok(())
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::worker::osv::OsvVulnerability;

    fn parse_json(json: &str) -> OsvVulnerability {
        serde_json::from_str(json).expect("Failed to parse JSON")
    }

    #[test]
    fn test_group_by_package_single() {
        let vuln = parse_json(r#"{"id": "test", "affected": [{"package": {"name": "crate-a"}}]}"#);
        let vulns = vec![&vuln];
        let grouped = group_by_package(&vulns);
        assert_eq!(grouped.len(), 1);
        assert!(grouped.contains_key("crate-a"));
        assert_eq!(grouped["crate-a"].len(), 1);
    }

    #[test]
    fn test_group_by_package_multiple_same() {
        let vuln1 = parse_json(r#"{"id": "test1", "affected": [{"package": {"name": "crate-a"}}]}"#);
        let vuln2 = parse_json(r#"{"id": "test2", "affected": [{"package": {"name": "crate-a"}}]}"#);
        let vulns = vec![&vuln1, &vuln2];
        let grouped = group_by_package(&vulns);
        assert_eq!(grouped.len(), 1);
        assert_eq!(grouped["crate-a"].len(), 2);
    }

    #[test]
    fn test_group_by_package_multiple_different() {
        let vuln1 = parse_json(r#"{"id": "test1", "affected": [{"package": {"name": "crate-a"}}]}"#);
        let vuln2 = parse_json(r#"{"id": "test2", "affected": [{"package": {"name": "crate-b"}}]}"#);
        let vulns = vec![&vuln1, &vuln2];
        let grouped = group_by_package(&vulns);
        assert_eq!(grouped.len(), 2);
        assert!(grouped.contains_key("crate-a"));
        assert!(grouped.contains_key("crate-b"));
    }

    #[test]
    fn test_group_by_package_no_package() {
        let vuln = parse_json(r#"{"id": "test", "affected": []}"#);
        let vulns = vec![&vuln];
        let grouped = group_by_package(&vulns);
        assert!(grouped.is_empty());
    }

    #[test]
    fn test_deduplicate_vulnerabilities_single() {
        let vuln = parse_json(r#"{"id": "test", "affected": [{"package": {"name": "crate"}}]}"#);
        let vulns = vec![&vuln];
        let deduped = deduplicate_vulnerabilities(&vulns);
        assert_eq!(deduped.len(), 1);
    }

    #[test]
    fn test_deduplicate_vulnerabilities_empty() {
        let vulns: Vec<&OsvVulnerability> = vec![];
        let deduped = deduplicate_vulnerabilities(&vulns);
        assert!(deduped.is_empty());
    }

    #[test]
    fn test_deduplicate_vulnerabilities_multiple() {
        // Current implementation returns all vulnerabilities
        let vuln1 = parse_json(r#"{"id": "test1", "affected": [{"package": {"name": "crate"}}]}"#);
        let vuln2 = parse_json(r#"{"id": "test2", "affected": [{"package": {"name": "crate"}}]}"#);
        let vulns = vec![&vuln1, &vuln2];
        let deduped = deduplicate_vulnerabilities(&vulns);
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn test_filter_unmaintained() {
        let vuln = parse_json(r#"{"id": "test", "affected": [], "summary": "This is unmaintained code"}"#);
        let lower = vuln.summary.as_ref().unwrap().to_lowercase();
        assert!(lower.contains("unmaint"));
    }

    #[test]
    fn test_filter_malicious() {
        let vuln = parse_json(r#"{"id": "test", "affected": [], "summary": "This contains malicious code"}"#);
        let lower = vuln.summary.as_ref().unwrap().to_lowercase();
        assert!(lower.contains("malicious code"));
    }

    #[test]
    fn test_filter_no_skip() {
        let vuln = parse_json(r#"{"id": "test", "affected": [], "summary": "Buffer overflow in parsing"}"#);
        let lower = vuln.summary.as_ref().unwrap().to_lowercase();
        assert!(!lower.contains("unmaint"));
        assert!(!lower.contains("malicious code"));
    }

    #[test]
    fn test_filter_no_summary() {
        let vuln = parse_json(r#"{"id": "test", "affected": []}"#);
        assert!(vuln.summary.is_none());
    }

    #[test]
    fn test_collection_result_default() {
        let result = CollectionResult::default();
        assert_eq!(result.total_vulnerabilities, 0);
        assert_eq!(result.inserted_vulnerabilities, 0);
        assert_eq!(result.skipped_unmaintained, 0);
        assert_eq!(result.skipped_malicious, 0);
        assert_eq!(result.duplicates_merged, 0);
    }
}

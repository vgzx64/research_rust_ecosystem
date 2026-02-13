//! Unit tests for Crustasystem models
//! 
//! This module contains comprehensive unit tests for all database models.
//! Run with: cargo test

// ============================================================================
// Handler Request/Response Tests
// ============================================================================

mod handler_tests {
    use serde::{Deserialize, Serialize};
    
    // Replicate handler types for testing
    #[derive(Deserialize, Debug)]
    pub struct ListQuery {
        pub limit: Option<u64>,
        pub offset: Option<u64>,
        pub package_name: Option<String>,
        pub severity_id: Option<i32>,
        pub type_id: Option<i32>,
    }
    
    #[derive(Deserialize, Serialize, Debug)]
    pub struct SearchQuery {
        pub id_type: String,
        pub id_value: String,
    }
    
    #[derive(Serialize, Debug)]
    pub struct VulnerabilityResponse {
        pub id: i32,
        pub package_name: String,
        pub severity_id: i32,
        pub type_id: i32,
        pub summary: Option<String>,
        pub details: Option<String>,
        pub published_at: Option<String>,
    }
    
    #[test]
    fn test_list_query_default_values() {
        let query = ListQuery {
            limit: None,
            offset: None,
            package_name: None,
            severity_id: None,
            type_id: None,
        };
        
        assert_eq!(query.limit, None);
        assert_eq!(query.offset, None);
        assert_eq!(query.package_name, None);
        assert_eq!(query.severity_id, None);
        assert_eq!(query.type_id, None);
    }
    
    #[test]
    fn test_list_query_with_filters() {
        let query = ListQuery {
            limit: Some(10),
            offset: Some(5),
            package_name: Some("tokio".to_string()),
            severity_id: Some(3),
            type_id: Some(1),
        };
        
        assert_eq!(query.limit, Some(10));
        assert_eq!(query.offset, Some(5));
        assert_eq!(query.package_name, Some("tokio".to_string()));
        assert_eq!(query.severity_id, Some(3));
        assert_eq!(query.type_id, Some(1));
    }
    
    #[test]
    fn test_search_query_parsing() {
        let query = SearchQuery {
            id_type: "GHSA".to_string(),
            id_value: "GHSA-c827-hfw6-qwvm".to_string(),
        };
        
        assert_eq!(query.id_type, "GHSA");
        assert_eq!(query.id_value, "GHSA-c827-hfw6-qwvm");
    }
    
    #[test]
    fn test_search_query_cve() {
        let query = SearchQuery {
            id_type: "CVE".to_string(),
            id_value: "CVE-2023-12345".to_string(),
        };
        
        assert_eq!(query.id_type, "CVE");
        assert_eq!(query.id_value, "CVE-2023-12345");
    }
    
    #[test]
    fn test_search_query_rustsec() {
        let query = SearchQuery {
            id_type: "RUSTSEC".to_string(),
            id_value: "RUSTSEC-2023-0048".to_string(),
        };
        
        assert_eq!(query.id_type, "RUSTSEC");
        assert_eq!(query.id_value, "RUSTSEC-2023-0048");
    }
    
    #[test]
    fn test_vulnerability_response_serialization() {
        let response = VulnerabilityResponse {
            id: 1,
            package_name: "tokio".to_string(),
            severity_id: 3,
            type_id: 1,
            summary: Some("Test vulnerability".to_string()),
            details: Some("Test details".to_string()),
            published_at: Some("2023-01-01T00:00:00".to_string()),
        };
        
        assert_eq!(response.id, 1);
        assert_eq!(response.package_name, "tokio");
        assert_eq!(response.severity_id, 3);
        assert_eq!(response.type_id, 1);
        assert!(response.summary.is_some());
        assert!(response.details.is_some());
        assert!(response.published_at.is_some());
    }
    
    #[test]
    fn test_vulnerability_response_minimal() {
        let response = VulnerabilityResponse {
            id: 42,
            package_name: "serde".to_string(),
            severity_id: 2,
            type_id: 5,
            summary: None,
            details: None,
            published_at: None,
        };
        
        assert_eq!(response.id, 42);
        assert_eq!(response.package_name, "serde");
        assert_eq!(response.severity_id, 2);
        assert_eq!(response.type_id, 5);
        assert!(response.summary.is_none());
        assert!(response.details.is_none());
        assert!(response.published_at.is_none());
    }
    
    #[test]
    fn test_list_query_serialization_deserialization() {
        let json = r#"{"limit":10,"offset":5,"package_name":"tokio","severity_id":3,"type_id":1}"#;
        let query: ListQuery = serde_json::from_str(json).unwrap();
        
        assert_eq!(query.limit, Some(10));
        assert_eq!(query.offset, Some(5));
        assert_eq!(query.package_name, Some("tokio".to_string()));
        assert_eq!(query.severity_id, Some(3));
        assert_eq!(query.type_id, Some(1));
    }
    
    #[test]
    fn test_search_query_serialization() {
        let query = SearchQuery {
            id_type: "GHSA".to_string(),
            id_value: "GHSA-xxxx".to_string(),
        };
        
        let json = serde_json::to_string(&query).unwrap();
        assert!(json.contains("GHSA"));
        assert!(json.contains("GHSA-xxxx"));
    }
}

// ============================================================================
// Model Data Structure Tests
// ============================================================================

mod model_tests {
    use serde::{Deserialize, Serialize};
    
    // Test severity level model
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SeverityLevel {
        pub id: i32,
        pub level: String,
        pub min_cvss: Option<f64>,
        pub max_cvss: Option<f64>,
    }
    
    #[test]
    fn test_severity_level_model() {
        let level = SeverityLevel {
            id: 1,
            level: "CRITICAL".to_string(),
            min_cvss: Some(9.0),
            max_cvss: Some(10.0),
        };
        
        assert_eq!(level.id, 1);
        assert_eq!(level.level, "CRITICAL");
        assert_eq!(level.min_cvss, Some(9.0));
        assert_eq!(level.max_cvss, Some(10.0));
    }
    
    #[test]
    fn test_severity_levels_valid() {
        let levels = vec![
            SeverityLevel { id: 1, level: "LOW".to_string(), min_cvss: Some(0.0), max_cvss: Some(3.9) },
            SeverityLevel { id: 2, level: "MEDIUM".to_string(), min_cvss: Some(4.0), max_cvss: Some(6.9) },
            SeverityLevel { id: 3, level: "HIGH".to_string(), min_cvss: Some(7.0), max_cvss: Some(8.9) },
            SeverityLevel { id: 4, level: "CRITICAL".to_string(), min_cvss: Some(9.0), max_cvss: Some(10.0) },
        ];
        
        assert_eq!(levels.len(), 4);
        assert_eq!(levels[0].level, "LOW");
        assert_eq!(levels[3].level, "CRITICAL");
    }
    
    // Test vulnerability type model
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct VulnerabilityType {
        pub id: i32,
        pub name: String,
        pub description: Option<String>,
    }
    
    #[test]
    fn test_vulnerability_type_model() {
        let vtype = VulnerabilityType {
            id: 1,
            name: "Memory Management".to_string(),
            description: Some("Memory related vulnerabilities".to_string()),
        };
        
        assert_eq!(vtype.id, 1);
        assert_eq!(vtype.name, "Memory Management");
        assert!(vtype.description.is_some());
    }
    
    #[test]
    fn test_all_vulnerability_types() {
        let types = vec![
            "Memory Management",
            "Memory Access",
            "Synchronization",
            "Tainted Input",
            "Resource Management",
            "Exception Management",
            "Cryptography",
            "Other",
            "Risky Values",
            "Path Resolution",
            "Information Leak",
            "Privilege",
            "Predictability",
            "Authentication",
            "API",
            "Access Control",
            "Failure to Release Memory",
        ];
        
        for (i, name) in types.iter().enumerate() {
            let vtype = VulnerabilityType {
                id: (i + 1) as i32,
                name: name.to_string(),
                description: None,
            };
            assert_eq!(vtype.name, *name);
        }
        assert_eq!(types.len(), 17);
    }
    
    // Test vulnerability model
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Vulnerability {
        pub id: i32,
        pub package_name: String,
        pub severity_id: i32,
        pub type_id: i32,
        pub summary: Option<String>,
        pub details: Option<String>,
        pub published_at: Option<String>,
    }
    
    #[test]
    fn test_vulnerability_model() {
        let vuln = Vulnerability {
            id: 1,
            package_name: "tokio".to_string(),
            severity_id: 3,
            type_id: 1,
            summary: Some("Memory leak".to_string()),
            details: Some("Details here".to_string()),
            published_at: Some("2023-01-01".to_string()),
        };
        
        assert_eq!(vuln.package_name, "tokio");
        assert_eq!(vuln.severity_id, 3);
    }
    
    #[test]
    fn test_vulnerability_minimal() {
        let vuln = Vulnerability {
            id: 1,
            package_name: "serde".to_string(),
            severity_id: 2,
            type_id: 3,
            summary: None,
            details: None,
            published_at: None,
        };
        
        assert!(vuln.summary.is_none());
        assert!(vuln.details.is_none());
    }
    
    // Test vulnerability IDs model
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct VulnerabilityId {
        pub id: i32,
        pub vulnerability_id: i32,
        pub id_type: String,
        pub id_value: String,
    }
    
    #[test]
    fn test_vulnerability_id_ghsa() {
        let id = VulnerabilityId {
            id: 1,
            vulnerability_id: 1,
            id_type: "GHSA".to_string(),
            id_value: "GHSA-c827-hfw6-qwvm".to_string(),
        };
        
        assert_eq!(id.id_type, "GHSA");
        assert_eq!(id.id_value, "GHSA-c827-hfw6-qwvm");
    }
    
    #[test]
    fn test_vulnerability_id_cve() {
        let id = VulnerabilityId {
            id: 1,
            vulnerability_id: 1,
            id_type: "CVE".to_string(),
            id_value: "CVE-2023-12345".to_string(),
        };
        
        assert_eq!(id.id_type, "CVE");
        assert_eq!(id.id_value, "CVE-2023-12345");
    }
    
    #[test]
    fn test_vulnerability_id_rustsec() {
        let id = VulnerabilityId {
            id: 1,
            vulnerability_id: 1,
            id_type: "RUSTSEC".to_string(),
            id_value: "RUSTSEC-2023-0048".to_string(),
        };
        
        assert_eq!(id.id_type, "RUSTSEC");
        assert_eq!(id.id_value, "RUSTSEC-2023-0048");
    }
    
    #[test]
    fn test_multiple_ids_for_vulnerability() {
        let ids = vec![
            VulnerabilityId { id: 1, vulnerability_id: 1, id_type: "GHSA".to_string(), id_value: "GHSA-1".to_string() },
            VulnerabilityId { id: 2, vulnerability_id: 1, id_type: "CVE".to_string(), id_value: "CVE-2023-1".to_string() },
            VulnerabilityId { id: 3, vulnerability_id: 1, id_type: "RUSTSEC".to_string(), id_value: "RUSTSEC-2023-1".to_string() },
        ];
        
        // All belong to same vulnerability
        assert_eq!(ids[0].vulnerability_id, ids[1].vulnerability_id);
        assert_eq!(ids[1].vulnerability_id, ids[2].vulnerability_id);
    }
    
    // Test package model
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Package {
        pub id: i32,
        pub name: String,
        pub repository_url: Option<String>,
        pub homepage: Option<String>,
        pub description: Option<String>,
        pub downloads: Option<i64>,
    }
    
    #[test]
    fn test_package_model() {
        let pkg = Package {
            id: 1,
            name: "tokio".to_string(),
            repository_url: Some("https://github.com/tokio-rs/tokio".to_string()),
            homepage: Some("https://tokio.rs".to_string()),
            description: Some("Async runtime".to_string()),
            downloads: Some(100_000_000),
        };
        
        assert_eq!(pkg.name, "tokio");
        assert!(pkg.downloads.is_some());
    }
    
    #[test]
    fn test_package_minimal() {
        let pkg = Package {
            id: 1,
            name: "serde".to_string(),
            repository_url: None,
            homepage: None,
            description: None,
            downloads: None,
        };
        
        assert_eq!(pkg.name, "serde");
        assert!(pkg.repository_url.is_none());
    }
    
    // Test fix commit model
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct FixCommit {
        pub id: i32,
        pub vulnerability_id: i32,
        pub commit_hash: String,
        pub repository_url: String,
        pub commit_message: Option<String>,
        pub committed_at: Option<String>,
        pub num_files_changed: Option<i32>,
        pub num_additions: Option<i32>,
        pub num_deletions: Option<i32>,
    }
    
    #[test]
    fn test_fix_commit_model() {
        let commit = FixCommit {
            id: 1,
            vulnerability_id: 1,
            commit_hash: "abc123def456".to_string(),
            repository_url: "https://github.com/tokio-rs/tokio".to_string(),
            commit_message: Some("Fix memory leak".to_string()),
            committed_at: Some("2023-01-01".to_string()),
            num_files_changed: Some(3),
            num_additions: Some(50),
            num_deletions: Some(20),
        };
        
        assert_eq!(commit.commit_hash.len(), 12);
        assert!(commit.num_files_changed.is_some());
    }
    
    #[test]
    fn test_commit_hash_formats() {
        // Full SHA-1
        let full_hash = "32b7fdfb7f542624ecd1f7c8d3e2b13c4e36a2c1";
        assert_eq!(full_hash.len(), 40);
        
        // Short hash
        let short_hash = "32b7fdf";
        assert_eq!(short_hash.len(), 7);
    }
    
    // Test file change model
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct FileChange {
        pub id: i32,
        pub fix_commit_id: i32,
        pub file_path: String,
        pub old_path: Option<String>,
        pub change_type: String,
        pub diff: Option<String>,
        pub num_additions: Option<i32>,
        pub num_deletions: Option<i32>,
    }
    
    #[test]
    fn test_file_change_types() {
        let types = vec!["added", "modified", "deleted", "renamed"];
        
        for change_type in types {
            let file = FileChange {
                id: 1,
                fix_commit_id: 1,
                file_path: "src/lib.rs".to_string(),
                old_path: None,
                change_type: change_type.to_string(),
                diff: None,
                num_additions: Some(5),
                num_deletions: Some(3),
            };
            assert_eq!(file.change_type, change_type);
        }
    }
    
    #[test]
    fn test_file_change_renamed() {
        let file = FileChange {
            id: 1,
            fix_commit_id: 1,
            file_path: "src/new_name.rs".to_string(),
            old_path: Some("src/old_name.rs".to_string()),
            change_type: "renamed".to_string(),
            diff: None,
            num_additions: Some(0),
            num_deletions: Some(0),
        };
        
        assert_eq!(file.old_path, Some("src/old_name.rs".to_string()));
    }
    
    #[test]
    fn test_file_path_formats() {
        let paths = vec![
            "src/lib.rs",
            "src/utils/helper.rs",
            "tests/integration_test.rs",
            "examples/http_client.rs",
        ];
        
        for path in paths {
            let file = FileChange {
                id: 1,
                fix_commit_id: 1,
                file_path: path.to_string(),
                old_path: None,
                change_type: "modified".to_string(),
                diff: None,
                num_additions: None,
                num_deletions: None,
            };
            assert_eq!(file.file_path, path);
        }
    }
    
    // Test function model
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Function {
        pub id: i32,
        pub fix_commit_id: i32,
        pub version: String,
        pub file_path: String,
        pub function_name: Option<String>,
        pub line_start: Option<i32>,
        pub line_end: Option<i32>,
        pub is_unsafe: Option<bool>,
        pub code_snippet: Option<String>,
    }
    
    #[test]
    fn test_function_versions() {
        let vulnerable = Function {
            id: 1,
            fix_commit_id: 1,
            version: "vulnerable".to_string(),
            file_path: "src/lib.rs".to_string(),
            function_name: Some("process".to_string()),
            line_start: Some(10),
            line_end: Some(25),
            is_unsafe: Some(true),
            code_snippet: Some("unsafe fn process() {}".to_string()),
        };
        
        let fixed = Function {
            id: 2,
            fix_commit_id: 1,
            version: "fixed".to_string(),
            file_path: "src/lib.rs".to_string(),
            function_name: Some("process".to_string()),
            line_start: Some(10),
            line_end: Some(30),
            is_unsafe: Some(false),
            code_snippet: Some("fn process() {}".to_string()),
        };
        
        assert_eq!(vulnerable.version, "vulnerable");
        assert_eq!(fixed.version, "fixed");
        assert!(vulnerable.is_unsafe.unwrap());
        assert!(!fixed.is_unsafe.unwrap());
    }
    
    // Test diff line model
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DiffLine {
        pub id: i32,
        pub file_change_id: i32,
        pub line_number: i32,
        pub content: String,
        pub line_type: String,
    }
    
    #[test]
    fn test_diff_line_types() {
        let added = DiffLine {
            id: 1,
            file_change_id: 1,
            line_number: 10,
            content: "+fn new_function() {".to_string(),
            line_type: "added".to_string(),
        };
        
        let deleted = DiffLine {
            id: 2,
            file_change_id: 1,
            line_number: 15,
            content: "-fn old_function() {".to_string(),
            line_type: "deleted".to_string(),
        };
        
        assert_eq!(added.line_type, "added");
        assert_eq!(deleted.line_type, "deleted");
        assert!(added.content.starts_with('+'));
        assert!(deleted.content.starts_with('-'));
    }
    
    // Test vulnerability statistics model
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct VulnerabilityStats {
        pub vulnerability_id: i32,
        pub vuln_safe_functions: Option<i32>,
        pub vuln_unsafe_functions: Option<i32>,
        pub vuln_unsafe_blocks: Option<i32>,
        pub fix_safe_functions: Option<i32>,
        pub fix_unsafe_functions: Option<i32>,
        pub fix_unsafe_blocks: Option<i32>,
        pub files_changed: Option<i32>,
        pub total_additions: Option<i32>,
        pub total_deletions: Option<i32>,
    }
    
    #[test]
    fn test_statistics_model() {
        let stats = VulnerabilityStats {
            vulnerability_id: 1,
            vuln_safe_functions: Some(100),
            vuln_unsafe_functions: Some(10),
            vuln_unsafe_blocks: Some(25),
            fix_safe_functions: Some(105),
            fix_unsafe_functions: Some(5),
            fix_unsafe_blocks: Some(10),
            files_changed: Some(3),
            total_additions: Some(50),
            total_deletions: Some(30),
        };
        
        assert_eq!(stats.vuln_safe_functions, Some(100));
        assert_eq!(stats.fix_safe_functions, Some(105));
    }
    
    #[test]
    fn test_statistics_unsafe_reduction() {
        let stats = VulnerabilityStats {
            vulnerability_id: 1,
            vuln_safe_functions: Some(100),
            vuln_unsafe_functions: Some(20),
            vuln_unsafe_blocks: Some(50),
            fix_safe_functions: Some(100),
            fix_unsafe_functions: Some(5),
            fix_unsafe_blocks: Some(10),
            files_changed: Some(2),
            total_additions: Some(30),
            total_deletions: Some(40),
        };
        
        let unsafe_reduction = stats.vuln_unsafe_functions.unwrap() - stats.fix_unsafe_functions.unwrap();
        assert_eq!(unsafe_reduction, 15);
        
        let block_reduction = stats.vuln_unsafe_blocks.unwrap() - stats.fix_unsafe_blocks.unwrap();
        assert_eq!(block_reduction, 40);
    }
}

// ============================================================================
// Helper Function Tests
// ============================================================================

mod helper_tests {
    #[test]
    fn test_id_type_detection() {
        fn detect_id_type(id_value: &str) -> &'static str {
            if id_value.starts_with("GHSA-") {
                "GHSA"
            } else if id_value.starts_with("CVE-") {
                "CVE"
            } else if id_value.starts_with("RUSTSEC-") {
                "RUSTSEC"
            } else {
                "OTHER"
            }
        }
        
        assert_eq!(detect_id_type("GHSA-c827-hfw6-qwvm"), "GHSA");
        assert_eq!(detect_id_type("CVE-2023-12345"), "CVE");
        assert_eq!(detect_id_type("RUSTSEC-2023-0048"), "RUSTSEC");
        assert_eq!(detect_id_type("UNKNOWN-123"), "OTHER");
    }
    
    #[test]
    fn test_version_range_parsing() {
        fn parse_version_range(range: &str) -> (Option<&str>, Option<&str>) {
            let parts: Vec<&str> = range.split(',').collect();
            
            let introduced = if parts[0].starts_with(">=") {
                Some(parts[0].trim_start_matches(">="))
            } else {
                None
            };
            
            let fixed = if parts.len() > 1 && parts[1].starts_with("<") {
                Some(parts[1].trim_start_matches("<"))
            } else if parts.len() == 1 && parts[0].starts_with("<") {
                Some(parts[0].trim_start_matches("<"))
            } else {
                None
            };
            
            (introduced, fixed)
        }
        
        assert_eq!(parse_version_range(">=1.0.0,<2.0.0"), (Some("1.0.0"), Some("2.0.0")));
        assert_eq!(parse_version_range(">=0.1.0"), (Some("0.1.0"), None));
        assert_eq!(parse_version_range("<1.0.0"), (None, Some("1.0.0")));
    }
    
    #[test]
    fn test_severity_level_calculation() {
        fn calculate_severity(cvss: f64) -> &'static str {
            if cvss >= 9.0 {
                "CRITICAL"
            } else if cvss >= 7.0 {
                "HIGH"
            } else if cvss >= 4.0 {
                "MEDIUM"
            } else {
                "LOW"
            }
        }
        
        assert_eq!(calculate_severity(10.0), "CRITICAL");
        assert_eq!(calculate_severity(9.5), "CRITICAL");
        assert_eq!(calculate_severity(8.5), "HIGH");
        assert_eq!(calculate_severity(7.0), "HIGH");
        assert_eq!(calculate_severity(6.5), "MEDIUM");
        assert_eq!(calculate_severity(4.0), "MEDIUM");
        assert_eq!(calculate_severity(3.9), "LOW");
        assert_eq!(calculate_severity(0.0), "LOW");
    }
    
    #[test]
    fn test_cvss_range_validation() {
        fn is_valid_cvss_range(min: f64, max: f64) -> bool {
            min >= 0.0 && max <= 10.0 && min <= max
        }
        
        assert!(is_valid_cvss_range(0.0, 3.9));
        assert!(is_valid_cvss_range(4.0, 6.9));
        assert!(is_valid_cvss_range(7.0, 8.9));
        assert!(is_valid_cvss_range(9.0, 10.0));
        
        assert!(!is_valid_cvss_range(-1.0, 3.9));
        assert!(!is_valid_cvss_range(0.0, 11.0));
        assert!(!is_valid_cvss_range(8.0, 7.0)); // min > max
    }
    
    #[test]
    fn test_change_type_validation() {
        fn is_valid_change_type(change_type: &str) -> bool {
            matches!(change_type, "added" | "modified" | "deleted" | "renamed")
        }
        
        assert!(is_valid_change_type("added"));
        assert!(is_valid_change_type("modified"));
        assert!(is_valid_change_type("deleted"));
        assert!(is_valid_change_type("renamed"));
        
        assert!(!is_valid_change_type("copied"));
        assert!(!is_valid_change_type("unknown"));
    }
    
    #[test]
    fn test_diff_line_prefix() {
        fn get_diff_type(content: &str) -> Option<&str> {
            if content.starts_with("+") {
                Some("added")
            } else if content.starts_with("-") {
                Some("deleted")
            } else if content.starts_with(" ") {
                Some("context")
            } else {
                None
            }
        }
        
        assert_eq!(get_diff_type("+fn new() {}"), Some("added"));
        assert_eq!(get_diff_type("-fn old() {}"), Some("deleted"));
        assert_eq!(get_diff_type(" context line"), Some("context"));
        assert_eq!(get_diff_type("@@"), None);
    }
}

// ============================================================================
// Run all tests with: cargo test --test models_test
// ============================================================================

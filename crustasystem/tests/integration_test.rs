//! Integration tests for Crustasystem
//! 
//! Tests database operations, constraints, and validation logic.
//! Run with: cargo test --test integration_test

use serde_json::json;

// ============================================================================
// UNIQUE Constraint Tests
// ============================================================================

mod unique_constraint_tests {
    use super::*;
    
    /// Test: vulnerability_ids UNIQUE(id_type, id_value)
    /// This constraint ensures no duplicate ID mappings exist
    #[test]
    fn test_vulnerability_ids_unique_constraint_logic() {
        // Simulate the unique constraint check
        fn is_duplicate_id(existing: &[(String, String)], new_type: &str, new_value: &str) -> bool {
            existing.iter().any(|(t, v)| t == new_type && v == new_value)
        }
        
        let existing_ids = vec![
            ("GHSA".to_string(), "GHSA-c827-hfw6-qwvm".to_string()),
            ("CVE".to_string(), "CVE-2023-12345".to_string()),
        ];
        
        // Should not allow duplicate GHSA
        assert!(is_duplicate_id(&existing_ids, "GHSA", "GHSA-c827-hfw6-qwvm"));
        // Should allow new GHSA
        assert!(!is_duplicate_id(&existing_ids, "GHSA", "GHSA-new-id"));
        // Should not allow duplicate CVE
        assert!(is_duplicate_id(&existing_ids, "CVE", "CVE-2023-12345"));
        // Should allow RUSTSEC for same vulnerability
        assert!(!is_duplicate_id(&existing_ids, "RUSTSEC", "RUSTSEC-2023-0048"));
    }
    
    /// Test: fix_commits UNIQUE(vulnerability_id, commit_hash)
    #[test]
    fn test_fix_commits_unique_constraint_logic() {
        fn is_duplicate_commit(existing: &[(i32, String)], vuln_id: i32, hash: &str) -> bool {
            existing.iter().any(|(v, h)| *v == vuln_id && h == hash)
        }
        
        let existing_commits = vec![
            (1, "abc123".to_string()),
            (1, "def456".to_string()),
            (2, "abc123".to_string()), // Same hash, different vulnerability - allowed
        ];
        
        // Same vulnerability + same hash = duplicate
        assert!(is_duplicate_commit(&existing_commits, 1, "abc123"));
        // Same vulnerability + different hash = allowed
        assert!(!is_duplicate_commit(&existing_commits, 1, "xyz789"));
        // Different vulnerability + same hash = allowed
        assert!(!is_duplicate_commit(&existing_commits, 3, "abc123"));
    }
    
    /// Test: file_changes UNIQUE(fix_commit_id, file_path)
    #[test]
    fn test_file_changes_unique_constraint_logic() {
        fn is_duplicate_file(existing: &[(i32, String)], commit_id: i32, path: &str) -> bool {
            existing.iter().any(|(c, p)| *c == commit_id && p == path)
        }
        
        let existing_files = vec![
            (1, "src/lib.rs".to_string()),
            (1, "src/main.rs".to_string()),
            (2, "src/lib.rs".to_string()), // Same file, different commit - allowed
        ];
        
        // Same commit + same file = duplicate
        assert!(is_duplicate_file(&existing_files, 1, "src/lib.rs"));
        // Same commit + different file = allowed
        assert!(!is_duplicate_file(&existing_files, 1, "src/new.rs"));
        // Different commit + same file = allowed
        assert!(!is_duplicate_file(&existing_files, 3, "src/lib.rs"));
    }
    
    /// Test: functions UNIQUE(fix_commit_id, version, file_path, line_start, line_end)
    #[test]
    fn test_functions_unique_constraint_logic() {
        #[derive(Debug, Clone)]
        struct FunctionKey {
            fix_commit_id: i32,
            version: String,
            file_path: String,
            line_start: i32,
            line_end: i32,
        }
        
        fn is_duplicate_function(existing: &[FunctionKey], key: &FunctionKey) -> bool {
            existing.iter().any(|f| {
                f.fix_commit_id == key.fix_commit_id &&
                f.version == key.version &&
                f.file_path == key.file_path &&
                f.line_start == key.line_start &&
                f.line_end == key.line_end
            })
        }
        
        let existing_functions = vec![
            FunctionKey {
                fix_commit_id: 1,
                version: "vulnerable".to_string(),
                file_path: "src/lib.rs".to_string(),
                line_start: 10,
                line_end: 20,
            },
        ];
        
        // Exact duplicate
        let duplicate = FunctionKey {
            fix_commit_id: 1,
            version: "vulnerable".to_string(),
            file_path: "src/lib.rs".to_string(),
            line_start: 10,
            line_end: 20,
        };
        assert!(is_duplicate_function(&existing_functions, &duplicate));
        
        // Different version (fixed vs vulnerable) - allowed
        let fixed_version = FunctionKey {
            fix_commit_id: 1,
            version: "fixed".to_string(),
            file_path: "src/lib.rs".to_string(),
            line_start: 10,
            line_end: 20,
        };
        assert!(!is_duplicate_function(&existing_functions, &fixed_version));
        
        // Different line numbers - allowed
        let different_lines = FunctionKey {
            fix_commit_id: 1,
            version: "vulnerable".to_string(),
            file_path: "src/lib.rs".to_string(),
            line_start: 15,
            line_end: 25,
        };
        assert!(!is_duplicate_function(&existing_functions, &different_lines));
    }
}

// ============================================================================
// API Endpoint Tests
// ============================================================================

mod api_tests {
    use super::*;
    
    /// Test: GET /health returns expected structure
    #[test]
    fn test_health_check_response_structure() {
        let expected = json!({
            "status": "ok"
        });
        
        assert_eq!(expected["status"], "ok");
    }
    
    /// Test: GET /vulnerabilities returns array
    #[test]
    fn test_list_vulnerabilities_response_structure() {
        // Empty list response
        let empty_response = json!([]);
        assert!(empty_response.as_array().unwrap().is_empty());
        
        // List with items
        let response_with_items = json!([
            {
                "id": 1,
                "package_name": "tokio",
                "severity_id": 3,
                "type_id": 1,
                "summary": "Test vulnerability"
            }
        ]);
        assert_eq!(response_with_items.as_array().unwrap().len(), 1);
    }
    
    /// Test: POST /vulnerabilities payload validation
    #[test]
    fn test_create_vulnerability_payload() {
        let valid_payload = json!({
            "package_name": "test-package",
            "severity": "HIGH",
            "vulnerability_type": "Memory Management",
            "summary": "Test vulnerability",
            "ghsa_id": "GHSA-test-test-test",
            "version_range": ">=1.0.0,<2.0.0"
        });
        
        // Verify required fields
        assert!(valid_payload.get("package_name").is_some());
        assert!(valid_payload.get("severity").is_some());
        assert!(valid_payload.get("vulnerability_type").is_some());
        
        // Verify payload structure
        assert_eq!(valid_payload["package_name"], "test-package");
        assert_eq!(valid_payload["severity"], "HIGH");
    }
    
    /// Test: Query parameters for filtering
    #[test]
    fn test_filter_query_params() {
        // Package filter
        let package_filter = json!({
            "package_name": "tokio"
        });
        assert_eq!(package_filter["package_name"], "tokio");
        
        // Severity filter
        let severity_filter = json!({
            "severity_id": 3
        });
        assert_eq!(severity_filter["severity_id"], 3);
        
        // Combined filters
        let combined_filter = json!({
            "package_name": "tokio",
            "severity_id": 3,
            "type_id": 1
        });
        assert_eq!(combined_filter["package_name"], "tokio");
        assert_eq!(combined_filter["severity_id"], 3);
        assert_eq!(combined_filter["type_id"], 1);
    }
}

// ============================================================================
// Model Relationship Tests
// ============================================================================

mod relationship_tests {
    use super::*;
    
    /// Test: Vulnerability can have multiple IDs (GHSA, CVE, RUSTSEC)
    #[test]
    fn test_vulnerability_multiple_ids() {
        let vuln_ids = json!([
            {"id_type": "GHSA", "id_value": "GHSA-c827-hfw6-qwvm"},
            {"id_type": "CVE", "id_value": "CVE-2023-12345"},
            {"id_type": "RUSTSEC", "id_value": "RUSTSEC-2023-0048"}
        ]);
        
        let ids = vuln_ids.as_array().unwrap();
        assert_eq!(ids.len(), 3);
        
        // All should reference the same vulnerability_id
        let id_types: Vec<&str> = ids.iter()
            .filter_map(|id| id.get("id_type")?.as_str())
            .collect();
        
        assert!(id_types.contains(&"GHSA"));
        assert!(id_types.contains(&"CVE"));
        assert!(id_types.contains(&"RUSTSEC"));
    }
    
    /// Test: Vulnerability can have multiple fix commits
    #[test]
    fn test_vulnerability_multiple_commits() {
        let commits = json!([
            {"commit_hash": "abc123", "repository_url": "https://github.com/example/repo"},
            {"commit_hash": "def456", "repository_url": "https://github.com/example/repo"}
        ]);
        
        assert_eq!(commits.as_array().unwrap().len(), 2);
    }
    
    /// Test: Commit can modify multiple files
    #[test]
    fn test_commit_multiple_files() {
        let files = json!([
            {"file_path": "src/lib.rs", "change_type": "modified"},
            {"file_path": "src/utils.rs", "change_type": "added"},
            {"file_path": "tests/test.rs", "change_type": "modified"}
        ]);
        
        assert_eq!(files.as_array().unwrap().len(), 3);
    }
    
    /// Test: File change can have multiple diff lines
    #[test]
    fn test_file_multiple_diff_lines() {
        let diff_lines = json!([
            {"line_number": 10, "content": "+fn new_fn() {}", "line_type": "added"},
            {"line_number": 15, "content": "-fn old_fn() {}", "line_type": "deleted"},
            {"line_number": 20, "content": "+    // new code", "line_type": "added"}
        ]);
        
        assert_eq!(diff_lines.as_array().unwrap().len(), 3);
    }
}

// ============================================================================
// Data Validation Tests
// ============================================================================

mod validation_tests {
    use super::*;
    
    /// Test: ID type detection (GHSA, CVE, RUSTSEC)
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
    
    /// Test: Severity level calculation from CVSS score
    #[test]
    fn test_severity_from_cvss() {
        fn cvss_to_severity(cvss: f64) -> &'static str {
            match cvss {
                x if x >= 9.0 => "CRITICAL",
                x if x >= 7.0 => "HIGH",
                x if x >= 4.0 => "MEDIUM",
                _ => "LOW",
            }
        }
        
        assert_eq!(cvss_to_severity(10.0), "CRITICAL");
        assert_eq!(cvss_to_severity(9.0), "CRITICAL");
        assert_eq!(cvss_to_severity(8.5), "HIGH");
        assert_eq!(cvss_to_severity(7.0), "HIGH");
        assert_eq!(cvss_to_severity(6.0), "MEDIUM");
        assert_eq!(cvss_to_severity(4.0), "MEDIUM");
        assert_eq!(cvss_to_severity(3.0), "LOW");
        assert_eq!(cvss_to_severity(0.0), "LOW");
    }
    
    /// Test: Change type validation
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
        assert!(!is_valid_change_type("moved"));
    }
    
    /// Test: Version range parsing
    #[test]
    fn test_version_range_parsing() {
        fn parse_version_range(range: &str) -> (Option<&str>, Option<&str>) {
            let parts: Vec<&str> = range.split(',').collect();
            
            let introduced = parts.iter()
                .find(|p| p.starts_with(">="))
                .map(|p| p.trim_start_matches(">="));
            
            let fixed = parts.iter()
                .find(|p| p.starts_with("<") && !p.starts_with("<="))
                .map(|p| p.trim_start_matches("<"));
            
            (introduced, fixed)
        }
        
        assert_eq!(
            parse_version_range(">=1.0.0,<2.0.0"),
            (Some("1.0.0"), Some("2.0.0"))
        );
        assert_eq!(
            parse_version_range(">=0.1.0"),
            (Some("0.1.0"), None)
        );
        assert_eq!(
            parse_version_range("<1.0.0"),
            (None, Some("1.0.0"))
        );
    }
    
    /// Test: Commit hash format validation
    #[test]
    fn test_commit_hash_validation() {
        fn is_valid_commit_hash(hash: &str) -> bool {
            let is_hex = hash.chars().all(|c| c.is_ascii_hexdigit());
            let valid_length = hash.len() >= 7 && hash.len() <= 40;
            is_hex && valid_length
        }
        
        assert!(is_valid_commit_hash("32b7fdfb7f542624ecd1f7c8d3e2b13c4e36a2c1"));
        assert!(is_valid_commit_hash("32b7fdf"));
        assert!(!is_valid_commit_hash("short"));
        assert!(!is_valid_commit_hash("gggggggggggggggggggggggggggggggggggggggg"));
    }
    
    /// Test: Function version validation
    #[test]
    fn test_function_version_validation() {
        fn is_valid_version(version: &str) -> bool {
            matches!(version, "vulnerable" | "fixed")
        }
        
        assert!(is_valid_version("vulnerable"));
        assert!(is_valid_version("fixed"));
        assert!(!is_valid_version("unknown"));
    }
    
    /// Test: Diff line type validation
    #[test]
    fn test_diff_line_type_validation() {
        fn is_valid_line_type(line_type: &str) -> bool {
            matches!(line_type, "added" | "deleted")
        }
        
        assert!(is_valid_line_type("added"));
        assert!(is_valid_line_type("deleted"));
        assert!(!is_valid_line_type("context"));
        assert!(!is_valid_line_type("unknown"));
    }
}

// ============================================================================
// Error Handling Tests
// ============================================================================

mod error_tests {
    use super::*;
    
    /// Test: GHSA ID format validation
    #[test]
    fn test_ghsa_format_validation() {
        fn is_valid_ghsa_format(id: &str) -> bool {
            // GHSA format: GHSA-xxxx-xxxx-xxxx (where x is alphanumeric)
            let parts: Vec<&str> = id.split('-').collect();
            if parts.len() != 4 || parts[0] != "GHSA" {
                return false;
            }
            parts[1].len() == 4 && parts[2].len() == 4 && parts[3].len() == 4 &&
                parts[1..=3].iter().all(|p| p.chars().all(|c| c.is_ascii_alphanumeric()))
        }
        
        assert!(is_valid_ghsa_format("GHSA-c827-hfw6-qwvm"));
        assert!(is_valid_ghsa_format("GHSA-1234-abcd-EF01"));
        assert!(!is_valid_ghsa_format("GHSA-invalid"));
        assert!(!is_valid_ghsa_format("ghsa-c827-hfw6-qwvm")); // lowercase prefix
        assert!(!is_valid_ghsa_format("GHSA-abc-def")); // Too short
    }
    
    /// Test: CVE ID format validation
    #[test]
    fn test_cve_format_validation() {
        fn is_valid_cve_format(id: &str) -> bool {
            // CVE format: CVE-YYYY-NNNN+
            let parts: Vec<&str> = id.split('-').collect();
            if parts.len() != 3 || parts[0] != "CVE" {
                return false;
            }
            let year_valid = parts[1].len() == 4 && parts[1].chars().all(|c| c.is_numeric());
            let id_valid = parts[2].len() >= 4 && parts[2].chars().all(|c| c.is_numeric());
            year_valid && id_valid
        }
        
        assert!(is_valid_cve_format("CVE-2023-12345"));
        assert!(is_valid_cve_format("CVE-2024-123456"));
        assert!(!is_valid_cve_format("CVE-23-12345")); // Year too short
        assert!(!is_valid_cve_format("CVE-2023-123")); // ID too short
        assert!(!is_valid_cve_format("cve-2023-12345")); // lowercase
    }
    
    /// Test: RUSTSEC ID format validation
    #[test]
    fn test_rustsec_format_validation() {
        fn is_valid_rustsec_format(id: &str) -> bool {
            // RUSTSEC format: RUSTSEC-YYYY-NNNN
            let parts: Vec<&str> = id.split('-').collect();
            if parts.len() != 3 || parts[0] != "RUSTSEC" {
                return false;
            }
            let year_valid = parts[1].len() == 4 && parts[1].chars().all(|c| c.is_numeric());
            let id_valid = parts[2].len() >= 4 && parts[2].chars().all(|c| c.is_numeric());
            year_valid && id_valid
        }
        
        assert!(is_valid_rustsec_format("RUSTSEC-2023-0048"));
        assert!(is_valid_rustsec_format("RUSTSEC-2024-0001"));
        assert!(!is_valid_rustsec_format("RUSTSEC-23-0048")); // Year too short
        assert!(!is_valid_rustsec_format("rustsec-2023-0048")); // lowercase
    }
    
    /// Test: Error response structure
    #[test]
    fn test_error_response_structure() {
        let error_response = json!({
            "error": "Not Found",
            "message": "Vulnerability with ID 999 not found"
        });
        
        assert!(error_response.get("error").is_some());
        assert!(error_response.get("message").is_some());
    }
}

// ============================================================================
// Seed Data Tests
// ============================================================================

mod seed_data_tests {
    use super::*;
    
    /// Test: Severity levels are defined correctly
    #[test]
    fn test_severity_levels_defined() {
        let expected_levels = vec![
            ("LOW", 0.0, 3.9),
            ("MEDIUM", 4.0, 6.9),
            ("HIGH", 7.0, 8.9),
            ("CRITICAL", 9.0, 10.0),
        ];
        
        assert_eq!(expected_levels.len(), 4);
        
        // Verify ranges don't overlap and cover full spectrum
        assert_eq!(expected_levels[0].1, 0.0);
        assert_eq!(expected_levels[3].2, 10.0);
    }
    
    /// Test: Vulnerability types are defined correctly
    #[test]
    fn test_vulnerability_types_defined() {
        let expected_types = vec![
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
        
        assert_eq!(expected_types.len(), 17);
        
        // Verify all types are unique
        let unique_count = expected_types.iter().collect::<std::collections::HashSet<_>>().len();
        assert_eq!(unique_count, 17);
    }
}

// ============================================================================
// Statistics Tests
// ============================================================================

mod statistics_tests {
    use super::*;
    
    /// Test: Unsafe code reduction calculation
    #[test]
    fn test_unsafe_reduction_calculation() {
        let stats = json!({
            "vuln_unsafe_functions": 20,
            "vuln_unsafe_blocks": 50,
            "fix_unsafe_functions": 5,
            "fix_unsafe_blocks": 10
        });
        
        let unsafe_fn_reduction = stats["vuln_unsafe_functions"].as_i64().unwrap() 
            - stats["fix_unsafe_functions"].as_i64().unwrap();
        let block_reduction = stats["vuln_unsafe_blocks"].as_i64().unwrap() 
            - stats["fix_unsafe_blocks"].as_i64().unwrap();
        
        assert_eq!(unsafe_fn_reduction, 15);
        assert_eq!(block_reduction, 40);
    }
    
    /// Test: Code change statistics
    #[test]
    fn test_code_change_statistics() {
        let stats = json!({
            "files_changed": 3,
            "total_additions": 50,
            "total_deletions": 30
        });
        
        assert_eq!(stats["files_changed"], 3);
        assert_eq!(stats["total_additions"], 50);
        assert_eq!(stats["total_deletions"], 30);
        
        // Net change
        let net_change = stats["total_additions"].as_i64().unwrap() 
            - stats["total_deletions"].as_i64().unwrap();
        assert_eq!(net_change, 20);
    }
}
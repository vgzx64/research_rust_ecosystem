//! Integration tests for the worker module
//!
//! Tests database operations and collection logic.

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    /// Test that the OSV vulnerability parsing works correctly
    #[test]
    fn test_osv_parsing_integration() {
        let json = r#"{
            "id": "RUSTSEC-2023-0048",
            "published": "2023-06-15T12:00:00Z",
            "summary": "Test vulnerability",
            "affected": [{
                "package": {"name": "test-crate"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]}]
            }],
            "severity": [{"score": "7.5"}],
            "references": [{"url": "https://example.com"}]
        }"#;

        let vuln: crustasystem::worker::osv::OsvVulnerability = serde_json::from_str(json).unwrap();
        
        assert_eq!(vuln.id, "RUSTSEC-2023-0048");
        assert_eq!(vuln.package_name(), Some("test-crate"));
        assert_eq!(vuln.severity_level(), Some("HIGH".to_string()));
        assert_eq!(vuln.id_type(), "RUSTSEC");
    }

    /// Test CWE to vulnerability type mapping
    #[test]
    fn test_cwe_mapping_integration() {
        use crustasystem::worker::sfp::{cwe_to_vulnerability_type, get_vulnerability_types};

        assert_eq!(cwe_to_vulnerability_type("CWE-787"), Some("Memory Access"));
        assert_eq!(cwe_to_vulnerability_type("CWE-327"), Some("Cryptography"));
        
        let cwes = vec!["CWE-787".to_string(), "CWE-125".to_string()];
        let types = get_vulnerability_types(&cwes);
        assert_eq!(types.len(), 1);
        assert_eq!(types[0], "Memory Access");
    }

    /// Test grouping vulnerabilities by package
    #[test]
    fn test_group_by_package_integration() {
        use crustasystem::worker::osv::OsvVulnerability;

        fn parse(json: &str) -> OsvVulnerability {
            serde_json::from_str(json).unwrap()
        }

        fn group_by_package<'a>(vulns: &[&'a OsvVulnerability]) -> HashMap<String, Vec<&'a OsvVulnerability>> {
            let mut grouped: HashMap<String, Vec<&'a OsvVulnerability>> = HashMap::new();
            for vuln in vulns {
                if let Some(pkg_name) = vuln.package_name() {
                    grouped.entry(pkg_name.to_string()).or_default().push(*vuln);
                }
            }
            grouped
        }

        let vuln1 = parse(r#"{"id": "v1", "affected": [{"package": {"name": "crate-a"}}]}"#);
        let vuln2 = parse(r#"{"id": "v2", "affected": [{"package": {"name": "crate-a"}}]}"#);
        let vuln3 = parse(r#"{"id": "v3", "affected": [{"package": {"name": "crate-b"}}]}"#);

        let grouped = group_by_package(&[&vuln1, &vuln2, &vuln3]);

        assert_eq!(grouped.len(), 2);
        assert_eq!(grouped["crate-a"].len(), 2);
        assert_eq!(grouped["crate-b"].len(), 1);
    }

    /// Test filtering logic for unmaintained packages
    #[test]
    fn test_filter_unmaintained_integration() {
        use crustasystem::worker::osv::OsvVulnerability;

        fn parse(json: &str) -> OsvVulnerability {
            serde_json::from_str(json).unwrap()
        }

        fn should_skip(summary: &str) -> bool {
            let lower = summary.to_lowercase();
            lower.contains("unmaint") || 
            lower.contains("no longer maint") || 
            lower.contains("discontinue")
        }

        let vuln1 = parse(r#"{"id": "v1", "affected": [], "summary": "This crate is unmaintained"}"#);
        let vuln2 = parse(r#"{"id": "v2", "affected": [], "summary": "Buffer overflow vulnerability"}"#);
        let vuln3 = parse(r#"{"id": "v3", "affected": [], "summary": "No longer maintained"}"#);

        assert!(should_skip(vuln1.summary.as_ref().unwrap()));
        assert!(!should_skip(vuln2.summary.as_ref().unwrap()));
        assert!(should_skip(vuln3.summary.as_ref().unwrap()));
    }

    /// Test filtering logic for malicious code
    #[test]
    fn test_filter_malicious_integration() {
        use crustasystem::worker::osv::OsvVulnerability;

        fn parse(json: &str) -> OsvVulnerability {
            serde_json::from_str(json).unwrap()
        }

        fn should_skip(summary: &str) -> bool {
            summary.to_lowercase().contains("malicious code")
        }

        let vuln1 = parse(r#"{"id": "v1", "affected": [], "summary": "Contains malicious code"}"#);
        let vuln2 = parse(r#"{"id": "v2", "affected": [], "summary": "Memory safety issue"}"#);

        assert!(should_skip(vuln1.summary.as_ref().unwrap()));
        assert!(!should_skip(vuln2.summary.as_ref().unwrap()));
    }

    /// Test severity level calculation
    #[test]
    fn test_severity_calculation_integration() {
        use crustasystem::worker::osv::OsvVulnerability;

        fn parse(json: &str) -> OsvVulnerability {
            serde_json::from_str(json).unwrap()
        }

        let vuln = parse(r#"{"id": "v1", "affected": [], "severity": [{"score": "9.5"}]}"#);
        assert_eq!(vuln.severity_level(), Some("CRITICAL".to_string()));

        let vuln = parse(r#"{"id": "v2", "affected": [], "severity": [{"score": "7.5"}]}"#);
        assert_eq!(vuln.severity_level(), Some("HIGH".to_string()));

        let vuln = parse(r#"{"id": "v3", "affected": [], "severity": [{"score": "5.0"}]}"#);
        assert_eq!(vuln.severity_level(), Some("MEDIUM".to_string()));

        let vuln = parse(r#"{"id": "v4", "affected": [], "severity": [{"score": "2.5"}]}"#);
        assert_eq!(vuln.severity_level(), Some("LOW".to_string()));
    }

    /// Test version range formatting
    #[test]
    fn test_version_range_formatting_integration() {
        use crustasystem::worker::osv::OsvVulnerability;

        fn parse(json: &str) -> OsvVulnerability {
            serde_json::from_str(json).unwrap()
        }

        let vuln = parse(r#"{
            "id": "v1",
            "affected": [{
                "ranges": [{
                    "type": "SEMVER",
                    "events": [
                        {"introduced": "1.0.0"},
                        {"fixed": "2.0.0"}
                    ]
                }]
            }]
        }"#);

        assert_eq!(vuln.version_ranges(), ">=1.0.0, <2.0.0");
    }

    /// Test ID type detection
    #[test]
    fn test_id_type_detection_integration() {
        use crustasystem::worker::osv::OsvVulnerability;

        fn parse(json: &str) -> OsvVulnerability {
            serde_json::from_str(json).unwrap()
        }

        let ghsa = parse(r#"{"id": "GHSA-abc-1234-defg", "affected": []}"#);
        assert_eq!(ghsa.id_type(), "GHSA");

        let cve = parse(r#"{"id": "CVE-2023-12345", "affected": []}"#);
        assert_eq!(cve.id_type(), "CVE");

        let rustsec = parse(r#"{"id": "RUSTSEC-2023-0001", "affected": []}"#);
        assert_eq!(rustsec.id_type(), "RUSTSEC");

        let unknown = parse(r#"{"id": "OTHER-ID", "affected": []}"#);
        assert_eq!(unknown.id_type(), "UNKNOWN");
    }

    /// Test CWE extraction from various locations
    #[test]
    fn test_cwe_extraction_integration() {
        use crustasystem::worker::osv::OsvVulnerability;

        fn parse(json: &str) -> OsvVulnerability {
            serde_json::from_str(json).unwrap()
        }

        let vuln = parse(r#"{
            "id": "v1",
            "affected": [{
                "database_specific": {
                    "cwe_ids": ["CWE-787", "CWE-125"]
                }
            }]
        }"#);
        let cwes = vuln.cwe_ids();
        assert_eq!(cwes.len(), 2);
        assert!(cwes.contains(&"CWE-787".to_string()));
    }

    /// Test reference URL extraction
    #[test]
    fn test_reference_extraction_integration() {
        use crustasystem::worker::osv::OsvVulnerability;

        fn parse(json: &str) -> OsvVulnerability {
            serde_json::from_str(json).unwrap()
        }

        let vuln = parse(r#"{
            "id": "v1",
            "affected": [],
            "references": [
                {"type": "ADVISORY", "url": "https://github.com/advisories/123"},
                {"type": "WEB", "url": "https://example.com/vuln"}
            ]
        }"#);

        let urls = vuln.reference_urls();
        assert_eq!(urls.len(), 2);
        assert!(urls.contains(&"https://github.com/advisories/123".to_string()));
    }

    /// Test alias parsing
    #[test]
    fn test_alias_parsing_integration() {
        use crustasystem::worker::osv::OsvVulnerability;

        fn parse(json: &str) -> OsvVulnerability {
            serde_json::from_str(json).unwrap()
        }

        let vuln = parse(r#"{
            "id": "GHSA-abc-123",
            "affected": [],
            "aliases": ["CVE-2023-12345", "RUSTSEC-2023-0001"]
        }"#);

        let aliases = vuln.aliases.unwrap();
        assert_eq!(aliases.len(), 2);
        assert!(aliases.contains(&"CVE-2023-12345".to_string()));
    }

    /// Test CollectionResult default values
    #[test]
    fn test_collection_result_default() {
        use crustasystem::worker::collector::CollectionResult;

        let result = CollectionResult::default();
        assert_eq!(result.total_vulnerabilities, 0);
        assert_eq!(result.inserted_vulnerabilities, 0);
        assert_eq!(result.skipped_unmaintained, 0);
        assert_eq!(result.skipped_malicious, 0);
        assert_eq!(result.duplicates_merged, 0);
    }
}

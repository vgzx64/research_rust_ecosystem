//! OSV (Open Source Vulnerabilities) data types
//! 
//! These types match the JSON structure from the OSV database dump.

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// Root vulnerability record from OSV
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OsvVulnerability {
    pub schema_version: Option<String>,
    pub id: String,
    pub published: Option<DateTime<Utc>>,
    pub modified: Option<DateTime<Utc>>,
    pub withdrawn: Option<DateTime<Utc>>,
    pub aliases: Option<Vec<String>>,
    pub related: Option<Vec<String>>,
    pub summary: Option<String>,
    pub details: Option<String>,
    pub affected: Vec<Affected>,
    pub references: Option<Vec<Reference>>,
    pub severity: Option<Vec<Severity>>,
    pub database_specific: Option<serde_json::Value>,
}

/// Affected package information
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Affected {
    pub package: Option<Package>,
    pub ranges: Option<Vec<Range>>,
    pub versions: Option<Vec<String>>,
    pub ecosystem_specific: Option<serde_json::Value>,
    pub database_specific: Option<serde_json::Value>,
    pub severity: Option<Vec<Severity>>,
}

/// Package identifier
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Package {
    pub name: String,
    pub ecosystem: Option<String>,
    pub purl: Option<String>,
}

/// Version range
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Range {
    #[serde(rename = "type")]
    pub range_type: String,
    pub repo: Option<String>,
    pub events: Vec<Event>,
}

/// Version event (introduced, fixed, etc.)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Event {
    pub introduced: Option<String>,
    pub fixed: Option<String>,
    pub limit: Option<String>,
    pub last_affected: Option<String>,
}

/// Reference URL
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Reference {
    #[serde(rename = "type")]
    pub ref_type: Option<String>,
    pub url: String,
}

/// Severity information
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Severity {
    #[serde(rename = "type")]
    pub severity_type: Option<String>,
    pub score: Option<String>,
}

impl OsvVulnerability {
    /// Get the package name from the first affected entry
    pub fn package_name(&self) -> Option<&str> {
        self.affected.first()?.package.as_ref().map(|p| p.name.as_str())
    }
    
    /// Get all version ranges as a formatted string
    pub fn version_ranges(&self) -> String {
        let ranges: Vec<String> = self.affected.iter()
            .filter_map(|a| {
                a.ranges.as_ref().map(|ranges| {
                    let events: Vec<String> = ranges.iter()
                        .filter_map(|r| {
                            let events: Vec<String> = r.events.iter()
                                .filter_map(|e| {
                                    if let Some(intro) = &e.introduced {
                                        Some(format!(">={}", intro))
                                    } else if let Some(fixed) = &e.fixed {
                                        Some(format!("<{}", fixed))
                                    } else {
                                        None
                                    }
                                })
                                .collect();
                            if events.is_empty() { None } else { Some(events.join(", ")) }
                        })
                        .collect();
                    if events.is_empty() { None } else { Some(events.join("; ")) }
                })
            })
            .flatten()
            .collect();
        
        ranges.join(" | ")
    }
    
    /// Get severity level from the vulnerability data
    pub fn severity_level(&self) -> Option<String> {
        // First check the severity array
        if let Some(severities) = &self.severity {
            for sev in severities {
                if let Some(score) = &sev.score {
                    return parse_cvss_severity(score);
                }
            }
        }
        
        // Then check database_specific in affected
        for affected in &self.affected {
            if let Some(db_spec) = &affected.database_specific {
                if let Some(cvss) = db_spec.get("cvss") {
                    if !cvss.is_null() {
                        if let Some(score) = cvss.as_str() {
                            return parse_cvss_severity(score);
                        } else if let Some(score) = cvss.as_f64() {
                            return cvss_score_to_severity(score);
                        }
                    }
                }
            }
        }
        
        // Then check database_specific at root level
        if let Some(db_spec) = &self.database_specific {
            if let Some(severity) = db_spec.get("severity") {
                if let Some(sev_str) = severity.as_str() {
                    return Some(normalize_severity(sev_str));
                }
            }
        }
        
        None
    }
    
    /// Get CWE IDs from the vulnerability data
    pub fn cwe_ids(&self) -> Vec<String> {
        let mut cwes = Vec::new();
        
        // Check database_specific in affected for cwe_ids
        for affected in &self.affected {
            if let Some(db_spec) = &affected.database_specific {
                if let Some(categories) = db_spec.get("categories") {
                    if let Some(arr) = categories.as_array() {
                        for cat in arr {
                            if let Some(cat_str) = cat.as_str() {
                                cwes.push(cat_str.to_string());
                            }
                        }
                    }
                }
                if let Some(cwe_ids) = db_spec.get("cwe_ids") {
                    if let Some(arr) = cwe_ids.as_array() {
                        for cwe in arr {
                            if let Some(cwe_str) = cwe.as_str() {
                                cwes.push(cwe_str.to_string());
                            }
                        }
                    }
                }
            }
        }
        
        // Check root database_specific for cwe_ids
        if let Some(db_spec) = &self.database_specific {
            if let Some(cwe_ids) = db_spec.get("cwe_ids") {
                if let Some(arr) = cwe_ids.as_array() {
                    for cwe in arr {
                        if let Some(cwe_str) = cwe.as_str() {
                            cwes.push(cwe_str.to_string());
                        }
                    }
                }
            }
        }
        
        cwes
    }
    
    /// Get all reference URLs
    pub fn reference_urls(&self) -> Vec<String> {
        self.references.as_ref()
            .map(|refs| refs.iter().map(|r| r.url.clone()).collect())
            .unwrap_or_default()
    }
    
    /// Parse the ID to determine its type (GHSA, CVE, RUSTSEC)
    pub fn id_type(&self) -> String {
        if self.id.starts_with("GHSA-") {
            "GHSA".to_string()
        } else if self.id.starts_with("CVE-") {
            "CVE".to_string()
        } else if self.id.starts_with("RUSTSEC-") {
            "RUSTSEC".to_string()
        } else {
            "UNKNOWN".to_string()
        }
    }
}

/// Parse CVSS score string and return severity level
fn parse_cvss_severity(score: &str) -> Option<String> {
    // Handle CVSS vector strings like "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    if score.starts_with("CVSS:") {
        // Extract base score from CVSS vector - this is complex, so we'll use a simple heuristic
        // For now, just return None and let the caller handle it
        return None;
    }
    
    // Try to parse as a numeric score
    if let Ok(numeric) = score.parse::<f64>() {
        return cvss_score_to_severity(numeric);
    }
    
    // Handle text severity levels
    Some(normalize_severity(score))
}

/// Convert CVSS numeric score to severity level
fn cvss_score_to_severity(score: f64) -> Option<String> {
    let severity = if score >= 9.0 {
        "CRITICAL"
    } else if score >= 7.0 {
        "HIGH"
    } else if score >= 4.0 {
        "MEDIUM"
    } else {
        "LOW"
    };
    Some(severity.to_string())
}

/// Normalize severity string to standard format
fn normalize_severity(sev: &str) -> String {
    let lower = sev.to_lowercase();
    match lower.as_str() {
        "critical" => "CRITICAL".to_string(),
        "high" => "HIGH".to_string(),
        "medium" | "moderate" => "MEDIUM".to_string(),
        "low" => "LOW".to_string(),
        _ => sev.to_uppercase(),
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_json(json: &str) -> OsvVulnerability {
        serde_json::from_str(json).expect("Failed to parse JSON")
    }

    #[test]
    fn test_parse_basic_vulnerability() {
        let json = r#"{"id": "GHSA-test-1234", "affected": []}"#;
        let vuln = parse_json(json);
        assert_eq!(vuln.id, "GHSA-test-1234");
    }

    #[test]
    fn test_package_name_extraction() {
        let json = r#"{"id": "test", "affected": [{"package": {"name": "my-crate"}}]}"#;
        let vuln = parse_json(json);
        assert_eq!(vuln.package_name(), Some("my-crate"));
    }

    #[test]
    fn test_package_name_empty_affected() {
        let json = r#"{"id": "test", "affected": []}"#;
        let vuln = parse_json(json);
        assert_eq!(vuln.package_name(), None);
    }

    #[test]
    fn test_version_ranges_basic() {
        let json = r#"{"id": "test", "affected": [{"ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]}]}]}"#;
        let vuln = parse_json(json);
        assert_eq!(vuln.version_ranges(), ">=1.0.0, <2.0.0");
    }

    #[test]
    fn test_version_ranges_empty() {
        let json = r#"{"id": "test", "affected": [{}]}"#;
        let vuln = parse_json(json);
        assert_eq!(vuln.version_ranges(), "");
    }

    #[test]
    fn test_severity_from_cvss_score() {
        let json = r#"{"id": "test", "affected": [], "severity": [{"score": "9.5"}]}"#;
        let vuln = parse_json(json);
        assert_eq!(vuln.severity_level(), Some("CRITICAL".to_string()));
    }

    #[test]
    fn test_severity_boundaries() {
        // Test CRITICAL boundary
        let vuln = parse_json(r#"{"id": "test", "affected": [], "severity": [{"score": "9.0"}]}"#);
        assert_eq!(vuln.severity_level(), Some("CRITICAL".to_string()));
        
        // Test HIGH boundary
        let vuln = parse_json(r#"{"id": "test", "affected": [], "severity": [{"score": "7.0"}]}"#);
        assert_eq!(vuln.severity_level(), Some("HIGH".to_string()));
        
        // Test MEDIUM boundary
        let vuln = parse_json(r#"{"id": "test", "affected": [], "severity": [{"score": "4.0"}]}"#);
        assert_eq!(vuln.severity_level(), Some("MEDIUM".to_string()));
        
        // Test LOW
        let vuln = parse_json(r#"{"id": "test", "affected": [], "severity": [{"score": "3.0"}]}"#);
        assert_eq!(vuln.severity_level(), Some("LOW".to_string()));
    }

    #[test]
    fn test_severity_from_text() {
        let json = r#"{"id": "test", "affected": [], "database_specific": {"severity": "high"}}"#;
        let vuln = parse_json(json);
        assert_eq!(vuln.severity_level(), Some("HIGH".to_string()));
    }

    #[test]
    fn test_severity_moderate_to_medium() {
        let json = r#"{"id": "test", "affected": [], "database_specific": {"severity": "moderate"}}"#;
        let vuln = parse_json(json);
        assert_eq!(vuln.severity_level(), Some("MEDIUM".to_string()));
    }

    #[test]
    fn test_cwe_ids_extraction() {
        let json = r#"{"id": "test", "affected": [{"database_specific": {"cwe_ids": ["CWE-787", "CWE-125"]}}]}"#;
        let vuln = parse_json(json);
        let cwes = vuln.cwe_ids();
        assert_eq!(cwes.len(), 2);
        assert!(cwes.contains(&"CWE-787".to_string()));
    }

    #[test]
    fn test_cwe_ids_empty() {
        let json = r#"{"id": "test", "affected": [{}]}"#;
        let vuln = parse_json(json);
        assert!(vuln.cwe_ids().is_empty());
    }

    #[test]
    fn test_reference_urls() {
        let json = r#"{"id": "test", "affected": [], "references": [{"url": "https://example.com"}]}"#;
        let vuln = parse_json(json);
        assert_eq!(vuln.reference_urls(), vec!["https://example.com"]);
    }

    #[test]
    fn test_reference_urls_empty() {
        let json = r#"{"id": "test", "affected": []}"#;
        let vuln = parse_json(json);
        assert!(vuln.reference_urls().is_empty());
    }

    #[test]
    fn test_id_type_ghsa() {
        let vuln = parse_json(r#"{"id": "GHSA-abc-123", "affected": []}"#);
        assert_eq!(vuln.id_type(), "GHSA");
    }

    #[test]
    fn test_id_type_cve() {
        let vuln = parse_json(r#"{"id": "CVE-2023-12345", "affected": []}"#);
        assert_eq!(vuln.id_type(), "CVE");
    }

    #[test]
    fn test_id_type_rustsec() {
        let vuln = parse_json(r#"{"id": "RUSTSEC-2023-0001", "affected": []}"#);
        assert_eq!(vuln.id_type(), "RUSTSEC");
    }

    #[test]
    fn test_id_type_unknown() {
        let vuln = parse_json(r#"{"id": "OTHER-123", "affected": []}"#);
        assert_eq!(vuln.id_type(), "UNKNOWN");
    }

    #[test]
    fn test_missing_optional_fields() {
        let vuln = parse_json(r#"{"id": "test", "affected": []}"#);
        assert!(vuln.summary.is_none());
        assert!(vuln.details.is_none());
        assert!(vuln.published.is_none());
        assert!(vuln.aliases.is_none());
    }

    #[test]
    fn test_aliases_parsing() {
        let json = r#"{"id": "test", "affected": [], "aliases": ["CVE-2023-123", "RUSTSEC-2023-001"]}"#;
        let vuln = parse_json(json);
        let aliases = vuln.aliases.unwrap();
        assert_eq!(aliases.len(), 2);
    }
}

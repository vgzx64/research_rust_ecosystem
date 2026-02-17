//! CWE to Vulnerability Type (SFP) mapping
//! 
//! This module maps CWE IDs to vulnerability types based on the
//! Software Fault Patterns (SFP) taxonomy used in the research.

use std::collections::HashMap;
use std::sync::LazyLock;

/// CWE ID to vulnerability type mapping
/// Based on the primary cluster mapping from the notebook
static CWE_TO_VULN_TYPE: LazyLock<HashMap<u32, &'static str>> = LazyLock::new(|| {
    let mut map = HashMap::new();
    
    // SFP1: Risky Values
    map.insert(843, "Risky Values");
    
    // SFP3: API
    map.insert(758, "API");
    
    // SFP4-6: Exception Management
    map.insert(908, "Exception Management");
    map.insert(909, "Exception Management");
    
    // SFP7-11: Memory Access
    map.insert(131, "Memory Access");
    map.insert(787, "Memory Access");
    map.insert(824, "Memory Access");
    map.insert(119, "Memory Access");
    map.insert(125, "Memory Access");
    
    // SFP12: Memory Management
    // (covered by category mapping)
    
    // SFP13-15: Resource Management
    map.insert(770, "Resource Management");
    map.insert(772, "Resource Management");
    map.insert(789, "Resource Management");
    
    // SFP16-18: Path Resolution
    map.insert(706, "Path Resolution");
    
    // SFP19-22: Synchronization
    map.insert(362, "Synchronization");
    
    // SFP23: Information Leak
    map.insert(668, "Information Leak");
    map.insert(200, "Information Leak");
    map.insert(203, "Information Leak");
    map.insert(208, "Information Leak");
    map.insert(377, "Information Leak");
    
    // SFP24-27: Tainted Input
    map.insert(129, "Tainted Input");
    map.insert(427, "Tainted Input");
    map.insert(172, "Tainted Input");
    map.insert(444, "Tainted Input");
    map.insert(198, "Tainted Input");
    map.insert(94, "Tainted Input");
    map.insert(351, "Tainted Input");
    
    // SFP29-34: Authentication
    map.insert(295, "Authentication");
    
    // SFP35: Access Control
    map.insert(279, "Access Control");
    
    // SFP36: Privilege
    map.insert(269, "Privilege");
    
    // SFP37: Faulty Resource Release (mapped to Failure to Release Memory)
    // SFP38: Failure to Release Memory
    
    // Cryptography
    map.insert(327, "Cryptography");
    map.insert(1240, "Cryptography");
    map.insert(347, "Cryptography");
    
    // Predictability
    map.insert(330, "Predictability");
    map.insert(338, "Predictability");
    map.insert(340, "Predictability");
    
    // Other
    map.insert(657, "Other");
    map.insert(670, "Other");
    map.insert(682, "Other");
    map.insert(697, "Other");
    map.insert(188, "Other");
    map.insert(193, "Other");
    map.insert(835, "Other");
    
    map
});

/// Get the vulnerability type name from a CWE ID or category
pub fn cwe_to_vulnerability_type(cwe: &str) -> Option<&'static str> {
    // Handle category-style names (from RustSec)
    if !cwe.starts_with("CWE-") {
        return category_to_vulnerability_type(cwe);
    }
    
    // Parse CWE number
    let cwe_num = cwe.strip_prefix("CWE-")
        .and_then(|s| s.parse::<u32>().ok())?;
    
    CWE_TO_VULN_TYPE.get(&cwe_num).copied()
}

/// Map RustSec category names to vulnerability types
fn category_to_vulnerability_type(category: &str) -> Option<&'static str> {
    let cat_lower = category.to_lowercase();
    match cat_lower.as_str() {
        "memory-exposure" => Some("Memory Access"),
        "memory-corruption" => Some("Memory Management"),
        "denial-of-service" => Some("Resource Management"),
        "file-disclosure" => Some("Path Resolution"),
        "thread-safety" => Some("Synchronization"),
        "format-injection" => Some("Tainted Input"),
        "privilege-escalation" => Some("Privilege"),
        "crypto-failure" => Some("Cryptography"),
        "code-execution" => Some("Other"),
        _ => None,
    }
}

/// Get all vulnerability types from a list of CWE IDs
pub fn get_vulnerability_types(cwes: &[String]) -> Vec<String> {
    let mut types: Vec<String> = cwes.iter()
        .filter_map(|cwe| cwe_to_vulnerability_type(cwe).map(|s| s.to_string()))
        .collect();
    types.sort();
    types.dedup();
    types
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cwe_to_vulnerability_type_known() {
        // Test known CWE mappings
        assert_eq!(cwe_to_vulnerability_type("CWE-787"), Some("Memory Access"));
        assert_eq!(cwe_to_vulnerability_type("CWE-125"), Some("Memory Access"));
        assert_eq!(cwe_to_vulnerability_type("CWE-362"), Some("Synchronization"));
        assert_eq!(cwe_to_vulnerability_type("CWE-327"), Some("Cryptography"));
        assert_eq!(cwe_to_vulnerability_type("CWE-295"), Some("Authentication"));
        assert_eq!(cwe_to_vulnerability_type("CWE-269"), Some("Privilege"));
    }

    #[test]
    fn test_cwe_to_vulnerability_type_unknown() {
        // Unknown CWE should return None
        assert_eq!(cwe_to_vulnerability_type("CWE-99999"), None);
        assert_eq!(cwe_to_vulnerability_type("CWE-0000"), None);
    }

    #[test]
    fn test_cwe_to_vulnerability_type_invalid_format() {
        // Invalid format should try category mapping
        assert_eq!(cwe_to_vulnerability_type("invalid"), None);
    }

    #[test]
    fn test_category_to_vulnerability_type() {
        // Test RustSec category mappings
        assert_eq!(cwe_to_vulnerability_type("memory-exposure"), Some("Memory Access"));
        assert_eq!(cwe_to_vulnerability_type("memory-corruption"), Some("Memory Management"));
        assert_eq!(cwe_to_vulnerability_type("denial-of-service"), Some("Resource Management"));
        assert_eq!(cwe_to_vulnerability_type("file-disclosure"), Some("Path Resolution"));
        assert_eq!(cwe_to_vulnerability_type("thread-safety"), Some("Synchronization"));
        assert_eq!(cwe_to_vulnerability_type("format-injection"), Some("Tainted Input"));
        assert_eq!(cwe_to_vulnerability_type("privilege-escalation"), Some("Privilege"));
        assert_eq!(cwe_to_vulnerability_type("crypto-failure"), Some("Cryptography"));
        assert_eq!(cwe_to_vulnerability_type("code-execution"), Some("Other"));
    }

    #[test]
    fn test_category_to_vulnerability_type_case_insensitive() {
        // Categories should be case-insensitive
        assert_eq!(cwe_to_vulnerability_type("Memory-Exposure"), Some("Memory Access"));
        assert_eq!(cwe_to_vulnerability_type("MEMORY-CORRUPTION"), Some("Memory Management"));
    }

    #[test]
    fn test_get_vulnerability_types_multiple() {
        let cwes = vec![
            "CWE-787".to_string(),
            "CWE-125".to_string(),
            "CWE-362".to_string(),
        ];
        let types = get_vulnerability_types(&cwes);
        assert_eq!(types.len(), 2); // Memory Access + Synchronization
        assert!(types.contains(&"Memory Access".to_string()));
        assert!(types.contains(&"Synchronization".to_string()));
    }

    #[test]
    fn test_get_vulnerability_types_dedup() {
        // Multiple CWEs mapping to same type should deduplicate
        let cwes = vec![
            "CWE-787".to_string(),
            "CWE-119".to_string(), // Both map to Memory Access
        ];
        let types = get_vulnerability_types(&cwes);
        assert_eq!(types.len(), 1);
        assert_eq!(types[0], "Memory Access");
    }

    #[test]
    fn test_get_vulnerability_types_empty() {
        let cwes: Vec<String> = vec![];
        let types = get_vulnerability_types(&cwes);
        assert!(types.is_empty());
    }

    #[test]
    fn test_get_vulnerability_types_unknown_only() {
        let cwes = vec!["CWE-99999".to_string()];
        let types = get_vulnerability_types(&cwes);
        assert!(types.is_empty());
    }

    #[test]
    fn test_get_vulnerability_types_mixed() {
        let cwes = vec![
            "CWE-787".to_string(),  // Known
            "CWE-99999".to_string(), // Unknown
            "CWE-327".to_string(),  // Known
        ];
        let types = get_vulnerability_types(&cwes);
        assert_eq!(types.len(), 2);
    }

    #[test]
    fn test_get_vulnerability_types_sorted() {
        let cwes = vec![
            "CWE-327".to_string(),  // Cryptography
            "CWE-787".to_string(),  // Memory Access
            "CWE-362".to_string(),  // Synchronization
        ];
        let types = get_vulnerability_types(&cwes);
        // Should be sorted alphabetically
        assert_eq!(types, vec!["Cryptography", "Memory Access", "Synchronization"]);
    }
}

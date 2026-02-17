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
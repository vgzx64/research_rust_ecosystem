//! Data collection worker module
//! 
//! This module contains the vulnerability data collection logic
//! that reads from local OSV data dumps and populates the database.

pub mod osv;
pub mod sfp;
pub mod collector;

pub use collector::collect_vulnerabilities;
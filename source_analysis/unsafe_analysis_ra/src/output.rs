use std::fs::{DirBuilder, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::SystemTime;

use anyhow::Result;

use crate::analyzer::AnalysisResult;

/// Write analysis results to files in the same format as the original tool
pub fn write_results(
    result: &AnalysisResult,
    output_dir: &Path,
    crate_name: &str,
    cve_id: &str,
    hash: &str,
) -> Result<()> {
    // Create the output directory structure
    let dir_path = output_dir.join(crate_name).join(cve_id).join(hash);
    DirBuilder::new()
        .recursive(true)
        .create(&dir_path)?;

    // Write functions file (01_functions)
    write_functions_file(result, &dir_path)?;

    // Write blocks file (02_blocks_in_function)
    write_blocks_file(result, &dir_path)?;

    // Write unsafe traits file (02_unsafe_traits)
    write_traits_file(result, &dir_path)?;

    // Write unsafe trait impls file (03_unsafe_traits_impls)
    write_trait_impls_file(result, &dir_path)?;

    Ok(())
}

/// Write the functions analysis file
fn write_functions_file(result: &AnalysisResult, dir_path: &Path) -> Result<()> {
    let filename = format!("01_functions_{}", timestamp());
    let file_path = dir_path.join(filename);
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(file_path)?;

    // Write metadata
    writeln!(file, "# of safe function: {}", result.safe_fn_count)?;
    writeln!(file, "# of unsafe function: {}", result.unsafe_fn_count)?;

    // Write each function as a JSON object
    for func in &result.functions {
        let serialized = serde_json::to_string_pretty(func)?;
        writeln!(file, "{}", serialized)?;
    }

    file.flush()?;
    file.sync_all()?;

    Ok(())
}

/// Write the blocks analysis file
fn write_blocks_file(result: &AnalysisResult, dir_path: &Path) -> Result<()> {
    let filename = format!("02_blocks_in_function_{}", timestamp());
    let file_path = dir_path.join(filename);
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(file_path)?;

    // Write metadata
    writeln!(file, "# of safe function/block: {}", result.safe_block_count)?;
    writeln!(file, "# of unsafe function/block: {}", result.unsafe_block_count)?;

    // Write each block group as a JSON array
    for block_group in &result.blocks {
        let serialized = serde_json::to_string(block_group)?;
        writeln!(file, "{}", serialized)?;
    }

    file.flush()?;
    file.sync_all()?;

    Ok(())
}

/// Write the unsafe traits file
fn write_traits_file(result: &AnalysisResult, dir_path: &Path) -> Result<()> {
    let filename = format!("02_unsafe_traits_{}", timestamp());
    let file_path = dir_path.join(filename);
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(file_path)?;

    for trait_ in &result.unsafe_traits {
        let serialized = serde_json::to_string_pretty(trait_)?;
        writeln!(file, "{}", serialized)?;
    }

    file.flush()?;
    file.sync_all()?;

    Ok(())
}

/// Write the unsafe trait impls file
fn write_trait_impls_file(result: &AnalysisResult, dir_path: &Path) -> Result<()> {
    let filename = format!("03_unsafe_traits_impls_{}", timestamp());
    let file_path = dir_path.join(filename);
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(file_path)?;

    for impl_ in &result.unsafe_trait_impls {
        let serialized = serde_json::to_string_pretty(impl_)?;
        writeln!(file, "{}", serialized)?;
    }

    file.flush()?;
    file.sync_all()?;

    Ok(())
}

/// Get a timestamp string for file naming
fn timestamp() -> u128 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}
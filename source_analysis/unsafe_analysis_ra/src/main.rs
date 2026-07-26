use std::env;
use std::path::Path;

use anyhow::Result;
use load_cargo::{load_workspace_at, LoadCargoConfig, ProcMacroServerChoice};
use project_model::CargoConfig;

mod analyzer;
mod output;

fn main() -> Result<()> {
    // Parse command-line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <project_path> <output_dir> [crate_name] [cve_id] [hash]", args[0]);
        std::process::exit(1);
    }

    let project_path = Path::new(&args[1]);
    let output_dir = Path::new(&args[2]);
    let crate_name = args.get(3).map(|s| s.as_str()).unwrap_or("");
    let cve_id = args.get(4).map(|s| s.as_str()).unwrap_or("");
    let hash = args.get(5).map(|s| s.as_str()).unwrap_or("");

    eprintln!("Analyzing project: {}", project_path.display());
    eprintln!("Output directory: {}", output_dir.display());

    // Load the Cargo workspace without full compilation
    let cargo_config = CargoConfig::default();
    let load_config = LoadCargoConfig {
        load_out_dirs_from_check: false,
        with_proc_macro_server: ProcMacroServerChoice::None,
        prefill_caches: true,
        num_worker_threads: 4,
        proc_macro_processes: 1,
    };

    let (db, vfs, _proc_macro) = load_workspace_at(
        project_path,
        &cargo_config,
        &load_config,
        &|msg| eprintln!("  {}", msg),
    )?;

    eprintln!("Workspace loaded successfully");

    // Run the analysis
    let analysis_result = analyzer::analyze(&db, &vfs, project_path)?;

    eprintln!(
        "Analysis complete: {} functions ({} safe, {} unsafe), {} unsafe blocks, {} unsafe traits, {} unsafe trait impls",
        analysis_result.functions.len(),
        analysis_result.safe_fn_count,
        analysis_result.unsafe_fn_count,
        analysis_result.unsafe_block_count,
        analysis_result.unsafe_traits.len(),
        analysis_result.unsafe_trait_impls.len(),
    );

    // Output results
    output::write_results(
        &analysis_result,
        output_dir,
        crate_name,
        cve_id,
        hash,
    )?;

    eprintln!("Results written to {}", output_dir.display());

    Ok(())
}
# Unsafe Analysis (rust-analyzer based)

A Rust static analysis tool that uses `rust-analyzer` as a library to detect unsafe code patterns without requiring full project compilation.

## Advantages over the original `unsafeAnalysis`

| Aspect | Original (compiler plugin) | New (rust-analyzer) |
|--------|--------------------------|---------------------|
| Compilation required | Yes (full `cargo check`) | No |
| Success rate | ~84% | ~100% (handles errors gracefully) |
| Speed | Minutes per project | Seconds per project |
| Macro expansion | Limited | Full (via rust-analyzer) |
| Cross-crate analysis | No | Yes |
| Nightly toolchain | Required | Not required |
| SYSROOT env var | Required | Not required |

## Building

```bash
cd source_analysis/unsafe_analysis_ra
cargo build --release
```

The binary will be at `target/release/unsafe_analysis_ra`.

## Usage

### Direct usage

```bash
./target/release/unsafe_analysis_ra <project_path> <output_dir> [crate_name] [cve_id] [hash]
```

### Via orchestration script

```bash
cd source_analysis/scripts
python analyze_project.py <datafile.csv>
```

The CSV should have columns: `hash`, `repo_url`, `cve_id`

## Output Format

The tool produces JSON files compatible with the original `format_result.py`:

- `01_functions_{timestamp}` — Function declarations (name, span, safe/unsafe)
- `02_blocks_in_function_{timestamp}` — Unsafe blocks within functions
- `02_unsafe_traits_{timestamp}` — Unsafe trait declarations
- `03_unsafe_traits_impls_{timestamp}` — Unsafe trait implementations

## Architecture

1. **`main.rs`** — Entry point, parses arguments, loads workspace, runs analysis
2. **`analyzer.rs`** — Core analysis logic using rust-analyzer's HIR API
3. **`output.rs`** — JSON output in the same format as the original tool

The tool uses:
- `load_cargo::load_workspace_at()` to load Cargo projects without compilation
- `hir::Function::is_unsafe()`, `hir::Trait::is_unsafe()` to detect unsafe items
- AST walking to find `unsafe {}` blocks within function bodies
- Source location mapping via `base_db::LineIndex`

## Dependencies

- `rust-analyzer` crates (loaded as local path dependencies from `../../rust-analyzer/crates/`)
- `decls` crate (local, for data structure definitions)
- `serde` + `serde_json` for JSON output
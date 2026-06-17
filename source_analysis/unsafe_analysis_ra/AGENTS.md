# Unsafe Analysis (rust-analyzer based) — Agent Guide

## Purpose
A Rust static analysis tool that uses `rust-analyzer` as a library to detect unsafe code patterns without requiring full project compilation. This replaces the legacy `unsafeAnalysis/` compiler plugin.

## Build & Run

```bash
cd source_analysis/unsafe_analysis_ra
cargo build --release
# Binary at: target/release/unsafe_analysis_ra

# Usage:
./target/release/unsafe_analysis_ra <project_path> <output_dir> [crate_name] [cve_id] [hash]
```

## Architecture

### Files
- **`src/main.rs`** — Entry point. Parses CLI args, loads workspace via `load_cargo::load_workspace_at()`, runs analysis, writes output.
- **`src/analyzer.rs`** — Core analysis logic. Walks HIR to find unsafe functions, blocks, traits, and trait impls.
- **`src/output.rs`** — Writes JSON files in the same format as the legacy compiler plugin.

### How it works
1. Uses `load_cargo::load_workspace_at()` with `ProcMacroServerChoice::None` and `load_out_dirs_from_check: false` — no compilation needed
2. Iterates over all crates → modules → declarations (functions, traits)
3. For each function: checks `func.is_unsafe(db)`, gets source location via `func.source(db)`
4. For each function body: recursively walks AST looking for `unsafe{}` blocks via `ast::BlockExpr` + `unsafe_token()`
5. For each trait: checks `trait.is_unsafe(db)`
6. For each impl: checks `impl.unsafe_token().is_some()` for unsafe trait implementations

### Key APIs used

| API | Purpose |
|-----|---------|
| `hir::Crate::all(db)` | Get all crates in workspace |
| `hir::Crate::modules(db)` | Get all modules in a crate |
| `hir::Module::declarations(db)` | Get all items declared in a module |
| `hir::Function::is_unsafe(db)` | Check if function is unsafe |
| `hir::Function::source(db)` | Get AST source of function |
| `hir::Function::name(db)` | Get function name |
| `hir::Function::module(db)` | Get containing module |
| `hir::Trait::is_unsafe(db)` | Check if trait is unsafe |
| `hir::Impl::all_in_crate(db, krate)` | Get all impl blocks in a crate |
| `HasSource::source(db)` | Get AST source with file ID |
| `ast::BlockExpr::unsafe_token()` | Check for `unsafe` keyword |
| `SourceDatabase::line_column()` | Convert byte offset to line number |
| `vfs::Vfs::file_path()` | Convert FileId to file path |
| `HirFileId::FileId(editioned)` → `editioned.file_id(db)` | Extract raw FileId from HirFileId |

## Output Format

Matches the legacy compiler plugin exactly:

### `01_functions_{timestamp}`
```
# of safe function: N
# of unsafe function: N
{"name":"fn_name","node_id":"mod::fn_name","header_span":"/path/file.rs:start-end","body_span":"/path/file.rs:start-end","unsafety":true}
```

### `02_blocks_in_function_{timestamp}`
```
# of safe function/block: N
# of unsafe function/block: N
[{"fn_id":"mod::fn_name","block_span":"/path/file.rs:start-end","unsafety":true}]
```

### `02_unsafe_traits_{timestamp}`
```
{"name":"TraitName","safe":false,"loc":"file: \"/path/file.rs\" line \"start-end\""}
```

### `03_unsafe_traits_impls_{timestamp}`
```
{"name":"TraitName","safe":false,"loc":"file: \"/path/file.rs\" line \"start-end\""}
```

## Output Directory Structure
```
{output_dir}/{crate_name}/{cve_id}/{hash}/
├── 01_functions_{timestamp}
├── 02_blocks_in_function_{timestamp}
├── 02_unsafe_traits_{timestamp}
└── 03_unsafe_traits_impls_{timestamp}
```

## Key Differences from Legacy `unsafeAnalysis/`

| Aspect | Legacy | New |
|--------|--------|-----|
| Requires compilation | Yes (`cargo check`) | No |
| Success rate | ~84% | ~100% |
| Nightly toolchain | Required | Not required |
| `SYSROOT` env var | Required | Not required |
| Binary type | Custom `rustc` binary | Standalone binary |
| Macro expansion | Limited | Full |
| Dependencies on `rustc` | Heavy pinned version | Stable rust-analyzer |
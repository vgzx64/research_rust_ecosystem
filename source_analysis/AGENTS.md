# Source Analysis — Agent Guide

## Purpose
Analyzes Rust source code to detect unsafe code patterns (unsafe functions, unsafe blocks, unsafe traits, unsafe trait implementations) in vulnerable repositories. This is the core of the research's empirical analysis.

## Directory Structure

```
source_analysis/
├── scripts/               # Python orchestration scripts
│   ├── analyze_project.py # NEW: rust-analyzer based orchestrator
│   ├── analyze_single.sh  # NEW: shell wrapper for new binary
│   ├── compile.py         # LEGACY: compiler plugin orchestrator
│   ├── compile_single.sh  # LEGACY: shell wrapper for old binary
│   ├── format_result.py   # Parses JSON output → MySQL database
│   ├── locate.py          # Maps unsafe code to vulnerability regions
│   ├── regex.py           # Regex fallback analysis
│   ├── check_head.sh      # Git checkout helper
│   └── worktree.sh        # Git worktree creation helper
├── decls/                 # Shared data structure definitions (Rust crate)
├── unsafeAnalysis/        # LEGACY: compiler plugin (requires compilation)
├── unsafe_analysis_ra/    # NEW: rust-analyzer based (no compilation)
└── tests/                 # Test Rust crate for validation
```

## Analysis Pipeline

### New (recommended) pipeline — no compilation required:
```
1. analyze_project.py reads fix_commits_final.csv
2. For each commit:
   a. checkout worktree at correct commit
   b. Run unsafe_analysis_ra binary (rust-analyzer based)
   c. Outputs JSON files to compiler_result_v3/{project}/{cve_id}/{hash}/
3. format_result.py parses JSON → MySQL tables
4. locate.py maps unsafe items to fix regions → vul_safe_unsafe table
```

### Legacy pipeline — requires full compilation:
```
1. compile.py reads fix_commits_final.csv
2. For each commit:
   a. checkout worktree at correct commit
   b. Run cargo +nightly check (with custom rustc plugin)
   c. Outputs JSON files to compiler_result_v2/{project}/{cve_id}/{hash}/
3. format_result.py parses JSON → MySQL tables
4. locate.py maps unsafe items to fix regions → vul_safe_unsafe table
```

### Regex fallback (when compilation fails):
```
regex.py → total_safe_unsafe_regex table (only aggregate counts)
```

## Output Format

Each analysis produces 4 files per crate per commit:

### `01_functions_{timestamp}`
```
# of safe function: N
# of unsafe function: N
{"name": "fn_name", "node_id": "...", "header_span": "path.rs: start-end", "body_span": "path.rs: start-end", "unsafety": true}
```

### `02_blocks_in_function_{timestamp}`
```
# of safe function/block: N
# of unsafe function/block: N
[{"fn_id": "mod::fn_name", "block_span": "path.rs: start-end", "unsafety": true}]
```

### `02_unsafe_traits_{timestamp}`
```
{"name": "TraitName", "safe": false, "loc": "file: \"path.rs\" line \"start-end\""}
```

### `03_unsafe_traits_impls_{timestamp}`
```
{"name": "TraitName", "safe": false, "loc": "file: \"path.rs\" line \"start-end\""}
```

## Key Script Details

### `format_result.py`
- Reads the JSON output files from analysis directories
- Formats them into DataFrames matching database schema
- Filters out external crate code (paths containing `/.cargo/` or `/rustc/`)
- Writes to MySQL tables: `function`, `function_fix`, `unsafe_block`, `unsafe_block_fix`, `total_safe_unsafe`

### `locate.py`
- Takes commit data and analysis results from the database
- For each fix commit, compares modified lines (deleted in VEC, added in VFC) with unsafe function/block spans
- Determines which unsafe items were affected by the fix
- Writes to `vul_safe_unsafe` table

## Database Tables Produced

| Table | Contents |
|-------|----------|
| `function` | Safe/unsafe functions in vulnerable code (before fix) |
| `function_fix` | Safe/unsafe functions in fixed code (after fix) |
| `unsafe_block` | Unsafe blocks in vulnerable code |
| `unsafe_block_fix` | Unsafe blocks in fixed code |
| `total_safe_unsafe` | Aggregate counts per vulnerability |
| `vul_safe_unsafe` | Vulnerability-to-unsafe-code mapping (from locate.py) |
| `total_safe_unsafe_regex` | Regex fallback aggregate counts |

## Build Commands

```bash
# Build the new rust-analyzer based analyzer
cd source_analysis/unsafe_analysis_ra && cargo build --release

# The legacy compiler plugin requires nightly:
cd source_analysis/unsafeAnalysis && cargo build --release
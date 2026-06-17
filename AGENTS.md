# Rust Ecosystem Vulnerability Research — Agent Guide

## Project Overview

This is an **academic research project** that systematically analyzes security vulnerabilities in the Rust software ecosystem. The dataset covers **433 vulnerabilities**, **300 vulnerable repositories**, and **218 fix commits** over 7 years.

### Key Research Findings
- ~2/3 of categorized vulnerabilities involve memory safety and concurrency issues
- Vulnerabilities take **>2 years on average** to be publicly disclosed
- **66.7%** have fixes committed before public disclosure
- Vulnerable code contains significantly more `unsafe` functions/blocks than safe code
- Fix commits are generally localized, with variation across vulnerability types

## Project Structure

```
root/
├── AGENTS.md              # This file
├── readme.md              # Research paper overview
├── PROJECT_AND_DATABASE_EXPLANATION.md  # Database schema docs
├── requirements.txt       # Python dependencies
├── tokens.yaml.example    # Example config for API tokens
│
├── data_collection/       # Step 1: Collect vulnerability advisories
├── data_extraction/       # Step 2: Mine fix commits and code changes
├── source_analysis/       # Step 3: Analyze unsafe code patterns
│   ├── scripts/           # Orchestration scripts
│   ├── decls/             # Shared data structures
│   ├── unsafeAnalysis/    # LEGACY: compiler-plugin (requires compilation)
│   ├── unsafe_analysis_ra/ # NEW: rust-analyzer based (no compilation)
│   └── tests/             # Test Rust crate
├── RQ/                    # Step 4: Research question notebooks
├── utils/                 # Shared Python utilities
├── regex_result/          # Regex-based analysis fallback results
├── repos_mirror/          # Cloned git repositories
├── repos_worktree/        # Git worktrees at specific commits
└── compiler_result_v2/    # Analysis output from old compiler plugin
```

## Data Pipeline

```
1. DATA COLLECTION (data_collection/)
   collect_vuls.ipynb → clones repos, parses OSV/CVE/GHSA advisories
   clone_repos.py     → mirrors all vulnerable repositories
   
2. DATA EXTRACTION (data_extraction/)
   extract_changes.py   → mines fix-commits, extracts diff hunks
   extract_life_span.py → computes vulnerability lifespan stats
   git_data_extractor.py→ git-based data extraction utilities
   collect_commits.ipynb→ orchestrates commit harvesting
   
3. SOURCE ANALYSIS (source_analysis/)
   compile.py  (LEGACY) → builds each project with custom rustc plugin
   OR
   analyze_project.py (NEW) → analyzes without compilation via rust-analyzer
   format_result.py    → parses JSON output into MySQL database
   locate.py           → locates unsafe code in vulnerable regions
   
4. RESEARCH QUESTIONS (RQ/)
   RQ1.ipynb  → Vulnerability characteristics and distributions
   RQ2.ipynb  → Unsafe code prevalence and vulnerability locality
   RQ3.ipynb  → Statistical analysis and comparisons
```

## Database

The project uses a **MySQL database** (`CVEfixes.db` in root) with tables managed via `utils/database.py`. Key tables:
- `cve` — Vulnerability advisories
- `crates`, `categories`, `crates_categories` — Crate metadata
- `versions` — Version history
- `file_change` — Per-file diff information
- `ext_commits` — Extended commit metadata
- `function`, `function_fix` — Function-level unsafe analysis
- `unsafe_block`, `unsafe_block_fix` — Block-level unsafe analysis
- `vul_safe_unsafe` — Vulnerability-to-unsafe-code mapping
- `total_safe_unsafe` — Aggregate counts

## Key Technical Notes

### Python Environment
- `.venv/` or `.venv-3.13/` virtual environments
- See `requirements.txt` for dependencies
- All Python scripts add `../../utils` to sys.path for shared utilities

### Git Worktree Approach
- Repos cloned to `repos_mirror/`
- Worktrees created in `repos_worktree/` at specific commits
- This allows analyzing historical commits without disturbing the main clone

### Analysis Methods (in priority order)
1. **rust-analyzer based** (NEW) — `unsafe_analysis_ra/` — No compilation needed
2. **Compiler plugin** (LEGACY) — `unsafeAnalysis/` — Requires full compilation
3. **Regex fallback** — `regex.py` — Simple text pattern matching

### Build Commands
```bash
# Build the rust-analyzer based analyzer
cd source_analysis/unsafe_analysis_ra && cargo build --release

# The binary is at: target/release/unsafe_analysis_ra
```

## Dependencies
- Python 3.10+ with: pandas, pydriller, click, toml, sqlalchemy, mysqlclient
- Rust nightly toolchain (for legacy compiler plugin)
- Rust stable toolchain (for rust-analyzer based analyzer)
- MySQL server for database

## For New Agents
Always check the `.clinerules/` directory at `/home/dev2/UbuntuTOolbox/Cline/Rules/` for global instructions. When working with Python, install dependencies only into the project's virtualenv.
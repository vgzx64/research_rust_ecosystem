# Deep Analysis: Research Methodology for Security Risks in the Rust Ecosystem

This is an **empirical mixed-methods study** examining security vulnerabilities in the Rust ecosystem over a 7-year period (2015-2022). The research compiles a comprehensive dataset and applies both quantitative and qualitative analyses.

---

## 1. Data Collection Methodology

### 1.1 Vulnerability Data Sources

The study aggregates vulnerability data from multiple sources:

1. **OSV (Open Source Vulnerabilities) API**
   - Downloads vulnerability data from `https://osv-vulnerabilities.storage.googleapis.com/crates.io/all.zip`
   - Transforms JSON files into a unified `vuls.json` (7.2MB)

2. **CWE (Common Weakness Enumeration) Mappings**
   - Downloads SFP (Software Fault Pattern) mappings from `https://cwe.mitre.org/data/csv/888.csv.zip`
   - Maps vulnerabilities to standardized categories

3. **crates.io Database**
   - Downloads full crates.io database dump (~1GB): `https://static.crates.io/db-dump.tar.gz`
   - Extracts package metadata: `crates.csv`, `versions.csv`, `categories.csv`

### 1.2 Repository Collection

- **clone_repos.py**: Clones vulnerable package repositories from GitHub/GitLab/etc.
- Creates working copies in `repos_worktree/` and mirrors in `repos_mirror/`

### 1.3 Dataset Statistics (from RQ1 analysis)

- **1,075 total vulnerabilities** in the database
- **821 categorized vulnerabilities** (with SFP classifications)
- Vulnerabilities span **1-4 categories** (median: 1, mean: 1.5)

---

## 2. Vulnerability Classification System

### 2.1 Primary Categories (Software Fault Patterns)

The study classifies vulnerabilities into SFP categories:

| Category | Count | Percentage |
|----------|-------|------------|
| Memory Management | 231 | 28.1% |
| Memory Access | 209 | 25.5% |
| Resource Management | 198 | 24.1% |
| Tainted Input | 115 | 14.0% |
| Synchronization | 90 | 11.0% |
| Cryptography | 79 | 9.6% |
| Other | 74 | 9.0% |
| Exception Management | 63 | 7.7% |
| Risky Values | 45 | 5.5% |
| Information Leak | 44 | 5.4% |
| Path Resolution | 42 | 5.1% |

### 2.2 Memory Safety Focus

- **Memory Synchronization Vulnerabilities**: 377 (45.9%)
- **Memory Concurrency Vulnerabilities**: 349 (42.5%)
- **Combined**: ~88% of categorized vulnerabilities relate to memory safety

---

## 3. Commit & Fix Extraction Pipeline

### 3.1 Reference Mining

The `collect_commits.ipynb` notebook extracts fix-related data from CVE references:
- **600 commits** identified
- **188 pull requests**
- **270 issues**
- Uses regex patterns to parse URLs from multiple git hosting services (GitHub, GitLab, BitBucket, Gitee, etc.)

### 3.2 LLM-Assisted Analysis

- Uses **DeepSeek Chat** (via OpenAI-compatible API) to:
  - Analyze commit messages
  - Identify vulnerability-fixing commits
  - Extract relevant context

### 3.3 Data Extraction Tools

- **extract_changes.py**: Analyzes diffs in fix commits
- **extract_life_span.py**: Calculates vulnerability lifecycle:
  - Introduction date (when vulnerability was introduced)
  - Fix date (when patch was committed)
  - Disclosure date (when publicly disclosed)

---

## 4. Source Code Analysis

### 4.1 Rust Compiler Plugin Approach

The study uses **Rust compiler internals** to analyze unsafe code:

1. **compile.py**: Invokes Rust compiler with custom plugins
2. **regex.py**: Parses and counts `unsafe` functions and blocks
3. **format_result.py**: Processes compilation output into structured data

### 4.2 Key Metrics Analyzed

- Location of `unsafe` functions and blocks
- Correlation between vulnerability and unsafe code presence
- Comparison: vulnerable code vs. complete package code

### 4.3 Compilation Results

- `compiler_result_v2/`: 379 directories with compilation results
- `success/`: List of successfully compiled packages
- `fail/`: List of failed compilations
- `manual.csv`: Manual annotations for complex cases

---

## 5. Research Questions (RQ) Analysis

### RQ1: Vulnerability Types, Lifespans, and Evolution

- Analyzes temporal distribution of vulnerabilities
- Tracks vulnerability category evolution over 7 years
- Examines disclosure patterns and timelines

### RQ2: Package Characteristics

- **Affected versions**: Which package versions are vulnerable
- **Popularity metrics**: Downloads, reverse dependencies
- **Categorization**: How vulnerabilities cluster by type
- **Affected code regions**: Where in the code vulnerabilities manifest

### RQ3: Fix Complexity and Locality

- **Code locality**: How localized are vulnerability fixes?
- **Fix patterns**: Differences across vulnerability types
- **Comparison**: How practitioners fix different vulnerability categories

---

## 6. Database Schema

The **CVEfixes.db** (2.7GB SQLite) contains:
- `cve` table: Vulnerability records with references, dates, severities
- `packages` table: Crate metadata
- `versions` table: Version-specific information
- `fix_commits` table: Git commit data for fixes

---

## 7. Supporting Infrastructure

### crustasystem (REST API)

Built with **Rust/Axum** framework:
- Provides programmatic access to vulnerability data
- Endpoints: `/vulnerabilities`, `/packages`, `/severity-levels`, `/vulnerability-types`
- OpenAPI/Swagger documentation
- Uses SeaORM for database access

### Frontend

- `crustasystem-frontend/`: Web interface for data exploration

---

## 8. Key Findings

1. **Memory safety dominance**: Two-thirds of vulnerabilities involve memory safety/concurrency
2. **Long disclosure timeline**: Vulnerabilities take >2 years to be publicly disclosed
3. **Pre-disclosure fixes**: 66.7% have fixes committed before public disclosure
4. **Unsafe code correlation**: Vulnerable code has significantly more `unsafe` functions/blocks

---

## 9. Reproducibility

The study provides complete reproducibility:

1. Python 3.13 with pandas 2.3.3
2. Jupyter notebooks in `RQ/` for all analyses
3. Downloadable dataset from Zenodo and Google Drive
4. All scripts and tools included

---

## Project Structure Summary

```
rust_ecosystem/
├── CVEfixes.db                    # Main SQLite database (2.7GB)
├── readme.md                       # Project overview
├── requirements.txt                # Python dependencies
│
├── data_collection/               # Vulnerability data collection
│   ├── collect_vuls.ipynb         # Main collection notebook (v1)
│   ├── collect_vuls_v2.ipynb      # Main collection notebook (v2)
│   ├── clone_repos.py             # Repository cloning script
│   ├── vuls.json                  # Raw vulnerability data (7.2MB)
│   ├── sfp.csv                    # CWE SFP mappings
│   └── crates_io_db/              # Downloaded crates.io database
│
├── data_extraction/               # Commit and fix extraction
│   ├── collect_commits.ipynb      # Mine vulnerability-fix commits
│   ├── extract_changes.py         # Extract code changes
│   ├── extract_life_span.py       # Extract vulnerability lifecycle
│   ├── fix_commits.csv            # Collected fix commits
│   └── git_data_extractor.py      # Git data extraction utilities
│
├── source_analysis/               # Source code analysis
│   ├── scripts/
│   │   ├── compile.py             # Rust compiler invocation
│   │   ├── regex.py               # Parse unsafe code
│   │   ├── format_result.py       # Format compilation results
│   │   └── locate.py              # Locate code regions
│   └── unsafeAnalysis/            # Compiler plugin for unsafe detection
│
├── RQ/                            # Research question analysis
│   ├── RQ1.ipynb                  # Vulnerability types & evolution
│   ├── RQ2.ipynb                  # Package characteristics
│   ├── RQ3.ipynb                  # Fix complexity & locality
│   └── fig/                       # Generated figures
│
├── crustasystem/                  # REST API server
│   ├── src/
│   │   ├── main.rs                # Axum server entry point
│   │   ├── handlers/               # HTTP handlers
│   │   └── models/                # Data models
│   └── Cargo.toml                 # Rust dependencies
│
├── repos_mirror/                 # Mirrored repositories (741 dirs)
├── repos_worktree/                # Working copies (379 dirs)
├── compiler_result_v2/            # Compilation results (379 dirs)
└── regex_result/                  # Regex analysis results (116 dirs)
```

---

This methodology represents a comprehensive, systematic approach to understanding ecosystem-level security risks, combining automated data collection, static analysis, and empirical research methods.

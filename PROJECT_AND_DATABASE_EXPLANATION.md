# Rust Ecosystem Security Research Project & CVEfixes.db Database Documentation

## Project Overview

This is an academic research project titled **"A Closer Look at the Security Risks in the Rust Ecosystem"**.

### Research Purpose
The project systematically examines security risks in the Rust software ecosystem using a mixed-methods approach. It analyzes:
- Vulnerability types, lifespans, and evolution
- Affected package versions and popularity
- Vulnerable code characteristics (especially unsafe code usage)
- Vulnerability fix complexity and code change locality
- Memory safety and concurrency issues which represent 2/3 of categorized vulnerabilities

### Key Findings
- Vulnerabilities take on average over 2 years to be publicly disclosed
- 66.7% of vulnerabilities have fixes committed BEFORE public disclosure
- Vulnerable code contains significantly more `unsafe` functions and blocks than regular code
- Fix commits are generally localized, with differences across vulnerability types

---

## CVEfixes.db Database Details

This is a **2.7 GB SQLite database** containing the complete research dataset with:
- 433 analyzed vulnerabilities
- 300 vulnerable code repositories
- 218 vulnerability fix commits
- 7 years of Rust ecosystem security data

---

### Database Tables & Contents

| Table Name | Purpose & Description |
|------------|------------------------|
| **cve2** | Main vulnerability table containing CVE/RUSTSEC advisory information: <br/>✅ Advisory ID, package name, repository URL <br/>✅ Publication/modification dates, vulnerable versions <br/>✅ Vulnerability summary, details, severity level, references |
| **commit_life_spans** | Tracks vulnerability timeline: <br/>✅ When vulnerability was introduced <br/>✅ When it was fixed <br/>✅ Maps commit hashes to CVEs |
| **ext_commits** | Detailed Git commit metadata for fix commits: <br/>✅ Commit message, merge status, parent commits <br/>✅ Number of changed files, line additions/deletions |
| **file_change** | Actual code changes from fix commits: <br/>✅ Full diff content, parsed changes <br/>✅ File paths before/after fix, change type |
| **function** | All functions found in vulnerable code versions: <br/>✅ Function name, file path, source code span <br/>✅ Safety status (safe / unsafe function) |
| **function_fix** | Function definitions in the *fixed* code version (for comparison) |
| **unsafe_block** | All `unsafe {}` blocks found in vulnerable code |
| **unsafe_block_fix** | `unsafe {}` blocks in the fixed code version |
| **total_safe_unsafe** | Aggregate counts: total safe/unsafe functions and blocks per commit |
| **total_safe_unsafe_regex** | Regex-based analysis results for safe/unsafe code statistics |
| **vul_safe_unsafe** | Side-by-side comparison table: <br/>✅ Unsafe/safe counts before vs after fix <br/>✅ Used to measure how fixes change unsafe code usage |

---

### Database Relationships
All tables are linked by:
- `cve_id` - Unique vulnerability identifier (CVE/RUSTSEC/GHSA number)
- `hash` - Git commit hash (both vulnerable and fixed commits)
- `repo_url` - Source code repository location

---

## Project Structure

| Directory | Purpose |
|-----------|---------|
| `data_collection/` | Scripts to gather vulnerability advisories, clone repositories |
| `data_extraction/` | Commit mining, fix extraction, lifespan calculation |
| `source_analysis/` | Rust compiler plugin for unsafe code analysis |
| `utils/` | Database connection and utilities, shared functions |
| `RQ/` | Jupyter notebooks for research questions (RQ1, RQ2, RQ3) and figure generation |
| `regex_result/` | Individual vulnerability analysis outputs organized by package and advisory |

---

## Usage Instructions

1. The database file `CVEfixes.db` is already present in this directory
2. Install dependencies from `requirements.txt`
3. Use the Jupyter notebooks in the `RQ/` folder to reproduce the research statistics and figures
4. The database can be queried directly using any SQLite client or via the Python utilities in `utils/database.py`

---

### Example Database Query
```sql
-- Count total vulnerabilities by severity
SELECT severity, COUNT(*) as count 
FROM cve2 
GROUP BY severity 
ORDER BY count DESC;
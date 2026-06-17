# Data Collection — Agent Guide

## Purpose
Collects vulnerability advisories from multiple sources (OSV, CVE, GHSA) and clones vulnerable repositories for analysis.

## Key Files

- **`collect_vuls.ipynb`** — Main data collection notebook:
  - Downloads `crates.io/all.zip` from OSV API → parses all Rust crate advisories
  - Downloads CWE/SFP mappings from cwe.mitre.org
  - Downloads crates.io database dump (crates, categories, versions metadata)
  - Joins OSV advisories with crates.io metadata (repo URLs, download counts)
  - Deduplicates vulnerabilities by grouping shared NVD/rustsec references
  - Filters out "unmaintained" and "malicious" advisories
  - Writes to database tables: `cve`, `crates`, `categories`, `crates_categories`, `versions`

- **`clone_repos.py`** — Clones all vulnerable repositories to `repos_mirror/`:
  - Reads CVE data from database
  - Clones via `pydriller.Git.clone_from()` for bare/working copies
  - Stores in `repos_mirror/{owner_repo}/` directory structure
  - Handles errors gracefully (skips unclonable repos)

## Outputs
- Database tables populated with vulnerability and crate metadata
- Cloned repositories in `repos_mirror/`
- Fix commits CSV (`data_collection/data/fix_commits_final.csv` or similar) consumed by data_extraction

## Key Technical Details
- Uses OSV API's bulk download (`/download/all.zip?epoch=1`) rather than per-advisory queries
- Relies on `get_full_project_name(repo_url)` from `utils/utils.py` to normalize URLs
- CWE-to-SFP mapping allows classifying vulnerabilities into Software Fault Pattern categories
- crates.io dump provides per-crate metadata: downloads, repository URL, categories, version history
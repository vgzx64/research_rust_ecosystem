# Data Extraction — Agent Guide

## Purpose
Mines fix commits from cloned repositories, extracts code changes (diff hunks), and computes vulnerability lifespan statistics.

## Key Files

- **`collect_commits.ipynb`** — Orchestrates commit harvesting:
  - Reads the fix commits CSV from data_collection
  - For each commit, uses pydriller to extract:
    - Diff hunks (added/deleted lines per file)
    - Commit metadata (author, date, message)
    - Parent commit info
  - Writes to database tables: `file_change`, `ext_commits`

- **`extract_changes.py`** — Extracts code changes from fix commits:
  - Uses pydriller to mine per-file diffs
  - Parses diff hunks into structured added/deleted line data
  - Stores results in `file_change` table with `diff_parsed` JSON column

- **`extract_life_span.py`** — Computes vulnerability lifespan:
  - Calculates time between introduction and fix for each vulnerability
  - Uses git blame to trace when vulnerable code was introduced
  - Outputs lifespan statistics

- **`git_data_extractor.py`** — Shared git data extraction utilities:
  - Helper functions for pydriller operations
  - Commit hash resolution, branch management
  - Diff parsing utilities

## Data Flow
```
data_collection/ → fix_commits_final.csv → collect_commits.ipynb → MySQL DB (file_change, ext_commits)
                                                              → extract_changes.py → file_change table
                                                              → extract_life_span.py → lifespan stats
```

## Key Technical Details
- Uses `pydriller.Git` for repository operations (different from raw `gitpython`)
- Diff parsing produces structured JSON with "added" and "deleted" line arrays
- Fix commits are mined twice: once for the vulnerable version (before fix) and once for the fixed version
- Shared utility functions in `git_data_extractor.py` handle common git operations
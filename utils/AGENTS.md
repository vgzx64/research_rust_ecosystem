# Utilities — Agent Guide

## Purpose
Shared Python utility modules used across the project.

## Key Files

### `database.py`
- **Purpose**: Provides database connection and write helpers for MySQL
- **Key functions**:
  - `conn` — Global MySQL database connection (configured via constants in `consts.py`)
  - `write_database(table_name, dataframe)` — Writes a pandas DataFrame to a MySQL table, handling schema mismatches
- **Usage**: `sys.path.append('../../utils')` then `import database as db`
- **Important**: Uses `df.to_sql()` with `if_exists='append'` for inserting data

### `utils.py`
- **Purpose**: General utility functions used across scripts
- **Key functions**:
  - `get_full_project_name(repo_url)` — Normalizes a GitHub URL to `{owner}_{repo}` format for directory naming
  - `is_git_repo(path)` — Checks if a path contains a valid git repository
  - `get_life_span()` — Computes vulnerability lifespan from commit data
  - `get_lifespan_statistics()` — Produces lifespan statistics
  - `get_latest(commit_dates)` — Returns the latest commit date
  - `get_oldest(commit_dates)` — Returns the oldest commit date
  - `cve_batch(batch_size)` — Batches CVE IDs for processing
  - `locate_modified_lines()` — Given file paths and line numbers, matches modified lines to function/block spans

### `consts.py`
- **Purpose**: Centralized configuration constants
- **Key constants**:
  - `DB_USER`, `DB_PASSWORD`, `DB_HOST`, `DB_PORT`, `DB_NAME` — MySQL connection parameters
  - `MYSQL_CONNECTION` — Pre-built connection URI for SQLAlchemy
  - `FIX_COMMITS_CSV` — Path to the fix commits CSV file
  - `REPOS_SOURCE_MIRROR`, `REPOS_SOURCE_WORKTREE` — Repository paths
  - `UNSAFE_FN_COUNT_BEFORE_FIX_FILE` — Path template for storing unsafe function counts

## How to Use
```python
import sys
sys.path.append('../../utils')
import database as db
from utils import get_full_project_name, is_git_repo

# Write a DataFrame to a database table
db.write_database("function", df_function_data)
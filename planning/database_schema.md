# Proposed Database Schema for LLM Fine-tuning Dataset

## Executive Summary

This document proposes a clean database schema to connect the currently fragmented vulnerability data, enabling efficient querying for LLM fine-tuning dataset generation.

---

## 1. Current Problems

### Problem 1: Broken Join Keys
The `commits` table stores `cve_id` as a string representation of a Python list:
```sql
-- Current (broken):
cve_id = "['GHSA-f632-vm87-2m2f']"
```

### Problem 2: Missing Foreign Keys
- `file_change` table has no `cve_id` column
- Must join through `commits` table, but that link is broken

### Problem 3: No Referential Integrity
- No foreign key constraints
- Duplicate tables exist (cve, cve2, cve_dup)

---

## 2. Proposed Schema

### 2.1 Lookup Tables (Seed Data)

#### severity_levels
Seeded table for CVSS severity levels.

```sql
CREATE TABLE severity_levels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    level TEXT UNIQUE NOT NULL,         -- 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    min_cvss REAL,
    max_cvss REAL
);

-- Seed data:
-- INSERT INTO severity_levels (level, min_cvss, max_cvss) VALUES
-- ('LOW', 0.0, 3.9),
-- ('MEDIUM', 4.0, 6.9),
-- ('HIGH', 7.0, 8.9),
-- ('CRITICAL', 9.0, 10.0);
```

#### vulnerability_types
Seeded table for vulnerability categories (from sfp_id field).

```sql
CREATE TABLE vulnerability_types (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,         -- 'Memory Management', 'Synchronization', etc.
    description TEXT
);

-- Seed data (from RQ1 analysis):
-- INSERT INTO vulnerability_types (name) VALUES
-- ('Memory Management'), ('Memory Access'), ('Synchronization'),
-- ('Tainted Input'), ('Resource Management'), ('Exception Management'),
-- ('Cryptography'), ('Other'), ('Risky Values'), ('Path Resolution'),
-- ('Information Leak'), ('Privilege'), ('Predictability'), 
-- ('Authentication'), ('API'), ('Access Control'), ('Failure to Release Memory');
```

---

### 2.2 Core Tables (3NF)

#### vulnerabilities
Central table for vulnerability records. All non-key attributes depend on the primary key.

```sql
CREATE TABLE vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    package_name TEXT NOT NULL,           -- FK to packages.name
    severity_id INTEGER NOT NULL,        -- FK to severity_levels.id
    type_id INTEGER NOT NULL,            -- FK to vulnerability_types.id
    summary TEXT,
    details TEXT,
    published_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (severity_id) REFERENCES severity_levels(id),
    FOREIGN KEY (type_id) REFERENCES vulnerability_types(id)
);
```

#### vulnerability_ids
All ID strings (GHSA ↔ CVE ↔ RUSTSEC) map to vulnerabilities.id (INTEGER).

```sql
CREATE TABLE vulnerability_ids (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vulnerability_id INTEGER NOT NULL,   -- FK to vulnerabilities.id (INTEGER)
    id_type TEXT NOT NULL,              -- 'GHSA', 'CVE', 'RUSTSEC'
    id_value TEXT NOT NULL,             -- The actual ID string
    
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id),
    UNIQUE(id_type, id_value)
);
```

#### affected_versions
Many-to-many: vulnerabilities affect multiple package versions.

```sql
CREATE TABLE affected_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vulnerability_id INTEGER NOT NULL,   -- FK to vulnerabilities.id
    version_range TEXT NOT NULL,        -- e.g., '>=1.0.0,<2.0.0'
    introduced_version TEXT,            -- First affected version
    fixed_version TEXT,                -- First fixed version
    
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id)
);
```

#### vulnerability_references
Many-to-many: vulnerabilities can have multiple reference URLs.

```sql
CREATE TABLE vulnerability_references (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vulnerability_id INTEGER NOT NULL,   -- FK to vulnerabilities.id
    url TEXT NOT NULL,
    
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id)
);
```

#### packages
All packages from crates.io

```sql
CREATE TABLE packages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    repository_url TEXT,
    homepage TEXT,
    description TEXT,
    downloads INTEGER,
    created_at DATETIME,
    updated_at DATETIME
);
```

---

### 2.3 Fix Commits Tables

#### fix_commits
Each vulnerability can have one or more fix commits.

```sql
CREATE TABLE fix_commits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vulnerability_id INTEGER NOT NULL REFERENCES vulnerabilities(id),  -- INTEGER FK
    commit_hash TEXT NOT NULL,
    repository_url TEXT NOT NULL,
    commit_message TEXT,
    committed_at DATETIME,
    num_files_changed INTEGER,
    num_additions INTEGER,
    num_deletions INTEGER,
    
    -- Metadata
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE(vulnerability_id, commit_hash)
);
```

#### file_changes
Files modified in each commit - supports multi-file fixes.

```sql
CREATE TABLE file_changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fix_commit_id INTEGER NOT NULL REFERENCES fix_commits(id),
    file_path TEXT NOT NULL,
    old_path TEXT,                   -- For renamed files
    change_type TEXT NOT NULL,       -- added, modified, deleted, renamed
    diff TEXT,                       -- Full diff with line numbers
    num_additions INTEGER,
    num_deletions INTEGER,
    
    UNIQUE(fix_commit_id, file_path)
);
```

#### diff_lines
Normalized diff lines - in 3NF (removed JSON column).

```sql
CREATE TABLE diff_lines (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_change_id INTEGER NOT NULL REFERENCES file_changes(id),
    line_number INTEGER NOT NULL,
    content TEXT NOT NULL,
    line_type TEXT NOT NULL,         -- 'added' or 'deleted'
    
    FOREIGN KEY (file_change_id) REFERENCES file_changes(id)
);

-- Example:
-- file_changes: id=1, file_path="src/lib.rs", num_additions=5, num_deletions=2
-- diff_lines:
-- | id | file_change_id | line_number | content      | line_type |
-- | 1  | 1              | 10          | +fn new_fn() | added     |
-- | 2  | 1              | 11          | +    ...     | added     |
-- | 3  | 1              | 15          | -fn old_fn() | deleted   |
```

---

### 2.4 Code Analysis Tables

#### functions
Extracted function information from compiler analysis.

```sql
CREATE TABLE functions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fix_commit_id INTEGER NOT NULL REFERENCES fix_commits(id),
    version TEXT NOT NULL,           -- 'vulnerable' or 'fixed'
    file_path TEXT NOT NULL,
    function_name TEXT,
    line_start INTEGER,
    line_end INTEGER,
    is_unsafe BOOLEAN,
    code_snippet TEXT,               -- Actual function code
    
    UNIQUE(fix_commit_id, version, file_path, line_start, line_end)
);
```

#### unsafe_blocks
Unsafe blocks within functions.

```sql
CREATE TABLE unsafe_blocks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    function_id INTEGER REFERENCES functions(id),
    fix_commit_id INTEGER NOT NULL REFERENCES fix_commits(id),
    version TEXT NOT NULL,           -- 'vulnerable' or 'fixed'
    block_type TEXT,                 -- 'unsafe block', 'unsafe fn', 'unsafe trait'
    line_start INTEGER,
    line_end INTEGER,
    code_snippet TEXT
);
```

---

### 2.5 Statistics Tables

#### vulnerability_statistics
Aggregated stats per vulnerability.

```sql
CREATE TABLE vulnerability_statistics (
    vulnerability_id INTEGER PRIMARY KEY REFERENCES vulnerabilities(id),
    
    -- Code statistics (vulnerable version)
    vuln_safe_functions INTEGER,
    vuln_unsafe_functions INTEGER,
    vuln_unsafe_blocks INTEGER,
    
    -- Code statistics (fixed version)
    fix_safe_functions INTEGER,
    fix_unsafe_functions INTEGER,
    fix_unsafe_blocks INTEGER,
    
    -- Fix characteristics
    files_changed INTEGER,
    total_additions INTEGER,
    total_deletions INTEGER
);
```

---

## 3. Entity Relationship Diagram (3NF)

```
┌─────────────────────┐     ┌─────────────────────┐
│  severity_levels    │     │  vulnerability_types │
├─────────────────────┤     ├─────────────────────┤
│ id (PK)            │     │ id (PK)            │
│ level               │     │ name               │
│ min_cvss            │     │ description        │
│ max_cvss            │     └─────────────────────┘
└────────┬────────────┘              ▲
         │                           │
         │ FK                        │ FK
         ▼                           │
┌─────────────────────┐         ┌─────────────────────┐
│     vulnerabilities │         │  affected_versions  │
├─────────────────────┤         ├─────────────────────┤
│ id (PK) INTEGER     │◄────────│ vulnerability_id    │
│ package_name (FK)   │    FK   │ version_range      │
│ severity_id (FK)    │         │ introduced_version │
│ type_id (FK)       │         │ fixed_version      │
│ summary             │         └─────────────────────┘
│ details             │
│ published_at        │
└────────┬────────────┘
         │
         │ FK
         ▼
┌─────────────────────┐
│   vulnerability_ids │
├─────────────────────┤
│ vulnerability_id (FK)│
│ id_type             │
│ id_value            │
└─────────────────────┘

         │
         │ FK
         ▼
┌──────────────────┐
│    fix_commits    │
├──────────────────┤
│ vulnerability_id  │
│ commit_hash (UK)  │
│ repository_url    │
└────────┬─────────┘
         │
         │ FK
         ▼
┌──────────────────┐
│   file_changes   │
├──────────────────┤
│ fix_commit_id (FK)
│ file_path        │
│ diff             │
└────────┬─────────┘
         │
         │ FK
         ▼
┌──────────────────┐
│    diff_lines    │
├──────────────────┤
│ file_change_id (FK)
│ line_number      │
│ content          │
│ line_type        │
└──────────────────┘

         │
         │ FK
         ▼
┌──────────────────┐
│    functions     │
├──────────────────┤
│ fix_commit_id (FK)
│ version          │
│ is_unsafe        │
└──────────────────┘
```

---

## 4. Migration Strategy

### Step 1: Create New Tables
```sql
CREATE TABLE vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    package_name TEXT NOT NULL,
    ...
);

CREATE TABLE vulnerability_ids (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vulnerability_id INTEGER NOT NULL,
    id_type TEXT NOT NULL,
    id_value TEXT NOT NULL,
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id),
    UNIQUE(id_type, id_value)
);
```

### Step 2: Parse and Migrate Data
```python
import ast

def detect_id_type(id_value):
    """Detect if ID is GHSA, CVE, or RUSTSEC"""
    if id_value.startswith('GHSA-'):
        return 'GHSA'
    elif id_value.startswith('CVE-'):
        return 'CVE'
    elif id_value.startswith('RUSTSEC-'):
        return 'RUSTSEC'
    return 'OTHER'

# Migrate: Parse "['GHSA-xxx', 'RUSTSEC-yyy']" → vulnerabilities + vulnerability_ids
for row in commits_table:
    cve_ids = ast.literal_eval(row['cve_id'])  # Parse string list
    
    # Insert into vulnerabilities (get integer ID)
    vuln_id = vulnerabilities.insert(
        package_name=row['package'],
        summary=row.get('summary', ''),
        ...
    )
    
    # Insert all ID strings into vulnerability_ids
    for cve_id in cve_ids:
        id_type = detect_id_type(cve_id)
        vulnerability_ids.insert(
            vulnerability_id=vuln_id,
            id_type=id_type,
            id_value=cve_id
        )
    
    # Insert into fix_commits (uses INTEGER vulnerability_id)
    fix_commits.insert(
        vulnerability_id=vuln_id,
        commit_hash=row['hash'],
        repo_url=row['repo_url']
    )
```

### Step 3: Add Missing Columns to file_changes
```sql
ALTER TABLE file_change ADD COLUMN vulnerability_id INTEGER;
UPDATE file_change 
SET vulnerability_id = (
    SELECT fc.vulnerability_id 
    FROM fix_commits fc 
    WHERE fc.hash = file_change.hash
);
```

### Step 4: Validate and Swap
- Verify all FK constraints
- Run test queries
- Swap table names

---

## 5. Example Queries for LLM Dataset

### Get vulnerability by any ID (GHSA, CVE, or RUSTSEC)
```sql
-- Find by GHSA ID
SELECT v.*, vi.id_value as ghsa_id
FROM vulnerabilities v
JOIN vulnerability_ids vi ON v.id = vi.vulnerability_id
WHERE vi.id_type = 'GHSA' AND vi.id_value = 'GHSA-c827-hfw6-qwvm';
```

### Get all code pairs for a vulnerability
```sql
SELECT 
    v.id as vulnerability_id,
    v.summary,
    v.vulnerability_types,
    fc.file_path,
    fc.diff,
    fc.change_type
FROM vulnerabilities v
JOIN fix_commits fc ON v.id = fc.vulnerability_id
JOIN file_changes fch ON fc.id = fch.fix_commit_id
WHERE v.id = 42;
```

### Get unsafe function changes
```sql
SELECT
    v.package_name,
    v.vulnerability_types,
    f_vuln.code_snippet as vulnerable_code,
    f_fix.code_snippet as fixed_code,
    f_vuln.is_unsafe as was_unsafe,
    f_fix.is_unsafe as now_unsafe
FROM vulnerabilities v
JOIN fix_commits fc ON v.id = fc.vulnerability_id
JOIN functions f_vuln ON fc.id = f_vuln.fix_commit_id AND f_vuln.version = 'vulnerable'
JOIN functions f_fix ON fc.id = f_fix.fix_commit_id AND f_fix.version = 'fixed'
WHERE f_vuln.function_name = f_fix.function_name;
```

---

## 6. Indexes for Performance

```sql
-- Vulnerability lookups
CREATE INDEX idx_vuln_package ON vulnerabilities(package_name);
CREATE INDEX idx_vuln_type ON vulnerabilities(vulnerability_types);

-- ID lookups (by any ID string)
CREATE INDEX idx_vuln_ids_type_value ON vulnerability_ids(id_type, id_value);

-- Commit lookups  
CREATE INDEX idx_commit_vuln ON fix_commits(vulnerability_id);
CREATE INDEX idx_commit_hash ON fix_commits(commit_hash);

-- File change lookups
CREATE INDEX idx_file_commit ON file_changes(fix_commit_id);
CREATE INDEX idx_file_path ON file_changes(file_path);

-- Function lookups
CREATE INDEX idx_func_commit ON functions(fix_commit_id);
CREATE INDEX idx_func_name ON functions(function_name);
```

---

*Document generated for database schema redesign*

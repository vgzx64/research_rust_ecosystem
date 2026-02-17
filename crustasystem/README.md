# Crustasystem - Vulnerability Database API

A REST API for managing Rust ecosystem vulnerability data, built with Axum and SeaORM.

## Quick Start

### 1. Create the Database

```bash
# From the crustasystem directory
cargo run --manifest-path migrations/Cargo.toml
```

This creates `crustasystem.db` with all tables, indexes, and seed data.

### 2. Run the API Server

```bash
cargo run
```

The server starts on `http://localhost:8080`.

### 3. Access Swagger UI

Open `http://localhost:8080/swagger-ui` in your browser for interactive API documentation.

## Database Migrations

### Migration Files

| File | Description |
|------|-------------|
| `m20260215_171037_create_new_schema.rs` | Creates all 13 tables with foreign keys |
| `m20260217_174900_add_constraints_and_indexes.rs` | Adds UNIQUE constraints and performance indexes |
| `m20260217_175000_seed_data.rs` | Inserts seed data (severity levels, vulnerability types) |

### Running Migrations

```bash
# Create fresh database
rm -f crustasystem.db
cargo run --manifest-path migrations/Cargo.toml

# Or with custom database path
DATABASE_URL="sqlite:///path/to/custom.db?mode=rwc" cargo run --manifest-path migrations/Cargo.toml
```

### Database Schema

```
┌─────────────────────┐
│   severity_level    │  (seeded: LOW, MEDIUM, HIGH, CRITICAL)
├─────────────────────┤
│ id, level, min_cvss, max_cvss
└─────────────────────┘
          ▲
          │ FK
          │
┌─────────────────────┐     ┌─────────────────────┐
│   vulnerability     │     │  vulnerability_type │  (seeded: 17 types)
├─────────────────────┤     ├─────────────────────┤
│ id, package_name    │◄────│ id, name, description│
│ severity_id (FK)    │     └─────────────────────┘
│ type_id (FK)        │
│ summary, details    │
│ published_at        │
└─────────────────────┘
          │
          │ FK
          ▼
┌─────────────────────┐
│  vulnerability_id   │  (GHSA, CVE, RUSTSEC mappings)
├─────────────────────┤
│ vulnerability_id    │
│ id_type, id_value   │
│ UNIQUE(id_type, id_value)
└─────────────────────┘
```

### Seed Data

**Severity Levels:**
| Level | CVSS Range |
|-------|------------|
| LOW | 0.0 - 3.9 |
| MEDIUM | 4.0 - 6.9 |
| HIGH | 7.0 - 8.9 |
| CRITICAL | 9.0 - 10.0 |

**Vulnerability Types (17):**
- Memory Management, Memory Access, Synchronization
- Tainted Input, Resource Management, Exception Management
- Cryptography, Other, Risky Values, Path Resolution
- Information Leak, Privilege, Predictability, Authentication
- API, Access Control, Failure to Release Memory

### Indexes

The following indexes are created for performance:

```sql
-- UNIQUE constraints
CREATE UNIQUE INDEX idx_vuln_ids_type_value ON vulnerability_id(id_type, id_value);
CREATE UNIQUE INDEX idx_fix_commits_vuln_hash ON fix_commit(vulnerability_id, commit_hash);
CREATE UNIQUE INDEX idx_file_changes_commit_path ON file_change(fix_commit_id, file_path);
CREATE UNIQUE INDEX idx_functions_unique ON function(fix_commit_id, version, file_path, line_start, line_end);

-- Performance indexes
CREATE INDEX idx_vuln_package ON vulnerability(package_name);
CREATE INDEX idx_commit_vuln ON fix_commit(vulnerability_id);
CREATE INDEX idx_commit_hash ON fix_commit(commit_hash);
CREATE INDEX idx_file_commit ON file_change(fix_commit_id);
CREATE INDEX idx_file_path ON file_change(file_path);
CREATE INDEX idx_func_commit ON function(fix_commit_id);
CREATE INDEX idx_func_name ON function(function_name);
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check |
| GET | `/severity-levels` | List all severity levels |
| GET | `/vulnerability-types` | List all vulnerability types |
| GET | `/packages/{name}` | Get package by name |
| POST | `/packages` | Create new package |
| GET | `/vulnerabilities` | List vulnerabilities (with filters) |
| POST | `/vulnerabilities` | Create new vulnerability |
| GET | `/vulnerabilities/{id}` | Get vulnerability by ID |

### Query Parameters

```
GET /vulnerabilities?package_name=tokio&severity_id=3&type_id=1
```

## Testing

```bash
# Run all tests
cargo test

# Run specific test file
cargo test --test integration_test
cargo test --test models_test
```

## Project Structure

```
crustasystem/
├── src/
│   ├── main.rs           # Application entry point
│   ├── db.rs             # Database state
│   ├── models/           # SeaORM entity definitions
│   │   ├── mod.rs
│   │   ├── severity_levels.rs
│   │   ├── vulnerability_types.rs
│   │   ├── vulnerabilities.rs
│   │   ├── vulnerability_ids.rs
│   │   ├── affected_versions.rs
│   │   ├── vulnerability_references.rs
│   │   ├── packages.rs
│   │   ├── fix_commits.rs
│   │   ├── file_changes.rs
│   │   ├── diff_lines.rs
│   │   ├── functions.rs
│   │   ├── unsafe_blocks.rs
│   │   └── vulnerability_statistics.rs
│   └── handlers/         # API route handlers
│       ├── mod.rs
│       ├── health.rs
│       ├── severity_levels.rs
│       ├── vulnerability_types.rs
│       ├── packages.rs
│       ├── vulnerabilities.rs
│       └── statistics.rs
├── migrations/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── main.rs
│       ├── m20260215_171037_create_new_schema.rs
│       ├── m20260217_174900_add_constraints_and_indexes.rs
│       └── m20260217_175000_seed_data.rs
├── tests/
│   ├── models_test.rs
│   └── integration_test.rs
├── Cargo.toml
└── README.md
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `sqlite://crustasystem.db?mode=rwc` | Database connection string |

## Dependencies

- **axum** - Web framework
- **sea-orm** - ORM with async support
- **sea-orm-migration** - Database migrations
- **tokio** - Async runtime
- **serde** - Serialization
- **utoipa** - OpenAPI documentation
- **tracing** - Logging
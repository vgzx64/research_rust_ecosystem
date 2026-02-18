#!/usr/bin/env bash
# Delete the existing database and re-run all migrations from scratch.
#
# Usage:
#   ./scripts/reset_db.sh
#
# Environment variables (all optional, defaults shown below):
#   DATABASE_URL - SQLite connection string (must include ?mode=rwc to create the file)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
MIGRATIONS_DIR="$PROJECT_DIR/migrations"

# ── Defaults ────────────────────────────────────────────────────────────────
DB_FILE="${DB_FILE:-${PROJECT_DIR}/crustasystem.db}"
DATABASE_URL="${DATABASE_URL:-sqlite://${DB_FILE}?mode=rwc}"
LOG_DIR="${LOG_DIR:-${PROJECT_DIR}/logs}"
TODAY="$(date +%Y-%m-%d)"

echo "[reset_db] DB file       : $DB_FILE"
echo "[reset_db] DATABASE_URL  : $DATABASE_URL"
echo "[reset_db] Log dir       : $LOG_DIR"
echo ""

# ── Delete old database ──────────────────────────────────────────────────────
if [[ -f "$DB_FILE" ]]; then
    echo "[reset_db] Removing existing database..."
    rm -f "$DB_FILE"
    echo "[reset_db] Removed $DB_FILE"
else
    echo "[reset_db] No existing database found, skipping removal."
fi

# ── Delete today's log files ─────────────────────────────────────────────────
LOG_PATTERN="${LOG_DIR}/worker.log.${TODAY}"
if compgen -G "$LOG_PATTERN" > /dev/null 2>&1; then
    echo "[reset_db] Removing today's log files (${TODAY})..."
    rm -f "$LOG_PATTERN"
    echo "[reset_db] Removed log files matching: $LOG_PATTERN"
else
    echo "[reset_db] No log files found for today (${TODAY}), skipping."
fi

# ── Run migrations ───────────────────────────────────────────────────────────
echo "[reset_db] Running migrations..."
DATABASE_URL="$DATABASE_URL" \
    /home/dev/.cargo/bin/cargo run \
        --manifest-path "$MIGRATIONS_DIR/Cargo.toml" \
        2>&1

echo ""
echo "[reset_db] Done. Database is ready at: $DB_FILE"

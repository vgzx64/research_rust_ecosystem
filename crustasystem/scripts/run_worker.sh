#!/usr/bin/env bash
# Run the vulnerability collection worker with debug logging.
#
# Usage:
#   ./scripts/run_worker.sh [--release]
#
# Environment variables (all optional, defaults shown below):
#   DATABASE_URL  - SQLite connection string
#   DATA_DIR      - Path to the data_collection directory
#   LOG_DIR       - Directory for rolling log files
#   RUST_LOG      - Log level filter

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# ── Defaults ────────────────────────────────────────────────────────────────
DATABASE_URL="${DATABASE_URL:-sqlite://${PROJECT_DIR}/crustasystem.db?mode=rwc}"
DATA_DIR="${DATA_DIR:-$(dirname "$PROJECT_DIR")/data_collection}"
LOG_DIR="${LOG_DIR:-${PROJECT_DIR}/logs}"
RUST_LOG="${RUST_LOG:-crustasystem=debug,sqlx=warn,info}"

# ── Cargo profile ───────────────────────────────────────────────────────────
CARGO_FLAGS=""
if [[ "${1:-}" == "--release" ]]; then
    CARGO_FLAGS="--release"
    echo "[run_worker] Building in release mode"
fi

echo "[run_worker] DATABASE_URL : $DATABASE_URL"
echo "[run_worker] DATA_DIR     : $DATA_DIR"
echo "[run_worker] LOG_DIR      : $LOG_DIR"
echo "[run_worker] RUST_LOG     : $RUST_LOG"
echo ""

export DATABASE_URL DATA_DIR LOG_DIR RUST_LOG

exec /home/dev/.cargo/bin/cargo run \
    --manifest-path "$PROJECT_DIR/Cargo.toml" \
    --bin worker \
    $CARGO_FLAGS

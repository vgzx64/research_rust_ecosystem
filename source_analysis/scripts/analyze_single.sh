#!/bin/bash
# Script to run the rust-analyzer based unsafe analysis on a single project.
# Usage: analyze_single.sh <project_path> <cve_id> <hash> <output_dir>
#
# Arguments:
#   $1 - Path to the project to analyze
#   $2 - CVE ID (or cve_id_fix for the fixed version)
#   $3 - Git commit hash
#   $4 - Output directory for analysis results

export CVE_ID="$2"
export HASH="$3"
export FULL_ANALYSIS_DIR="$4"

# Path to the new analysis binary
ANALYSIS_BIN="$(dirname "$0")/../unsafe_analysis_ra/target/release/unsafe_analysis_ra"

# Check if the binary exists
if [ ! -f "$ANALYSIS_BIN" ]; then
    echo "Error: Analysis binary not found at $ANALYSIS_BIN"
    echo "Please build it first: cd ../unsafe_analysis_ra && cargo build --release"
    exit 1
fi

# Create output directory if it doesn't exist
if [ ! -d "$FULL_ANALYSIS_DIR" ]; then
    mkdir -p "$FULL_ANALYSIS_DIR"
fi

# Run the analysis
cd "$1"
"$ANALYSIS_BIN" "$1" "$FULL_ANALYSIS_DIR" "" "$CVE_ID" "$HASH"
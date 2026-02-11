#!/bin/bash

# Find all directories immediately inside the current directory (.)
# -maxdepth 1: Do not go deeper than the immediate subdirectories.
# -mindepth 1: Do not include the current directory (.) itself.
# -type d: Only look for directories.
# -print0: Separate output with null bytes (handles filenames with spaces/newlines safely).

find . -maxdepth 1 -mindepth 1 -type d -print0 | while IFS= read -r -d '' dir; do
    
    # Check if the directory contains any non-empty files.
    # -type f: Look for files only.
    # -size +0: Look for files with size greater than 0 bytes.
    # -print -quit: Print the name of the first match and stop searching (optimization).
    # If the output is empty (-z), it means no non-empty files were found.
    
    if [ -z "$(find "$dir" -type f -size +0 -print -quit)" ]; then
        echo "Deleting directory: $dir"
        rm -rf "$dir"
    fi

done
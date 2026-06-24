"""
extract_life_span.py — Compute vulnerability lifespan (introduction → fix date).

For each fix commit in the database, this script:
  1. Finds the fix date (committer date of the fix commit).
  2. Uses `git blame` on each deleted line (from the fix diff) to trace back
     to the commit that *introduced* that line.
  3. Takes the earliest introducer commit date as the vulnerability's
     introduction date.
  4. Writes the result to the `commit_life_spans` table.

Lifespan = fix_date - introduced_date  (computed downstream in analysis).
"""

from __future__ import annotations

import ast
import json
import logging
import os
import sys
from typing import Optional

import pandas as pd
from git import Repo
from git.exc import GitCommandError
from pydriller import Git as PydrillerGit
from tqdm import tqdm

sys.path.append("../utils")
import database as db  # noqa: E402
from utils import get_full_project_name, is_git_repo  # noqa: E402

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
REPOS_MIRROR = "../repos_mirror"

# Path components that indicate a file is test/example/doc and should be
# excluded from blame analysis.
_SKIP_PATH_SEGMENTS = {"test", "example", "doc", "docs", "bench", "benches"}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _should_skip_path(filepath: str) -> bool:
    """Return True if *filepath* contains a segment we skip (test, example, …)."""
    if pd.isna(filepath) or filepath == "None":
        return True
    parts = filepath.replace("\\", "/").split("/")
    return bool(_SKIP_PATH_SEGMENTS & set(parts))


def _blame_introducers(
    repo: Repo, parent_hash: str, filepath: str, deleted_lines: list[tuple[int, str]]
) -> set[str]:
    """
    Run ``git blame -w <parent_hash>^ -- <filepath>`` and return the set of
    commit hashes that introduced the *deleted_lines*.

    Lines whose content starts with ``//`` (comments) or whose blame result
    starts with ``*`` (unblamable) are skipped.

    Parameters
    ----------
    repo : Repo
        GitPython Repo handle.
    parent_hash : str
        The fix commit hash; we blame its parent (``<hash>^``) so we see the
        state *before* the fix.
    filepath : str
        Path relative to repo root.
    deleted_lines : list of (int, str)
        (1-based line number, content) pairs from the fix diff's deleted lines.

    Returns
    -------
    set of str
        Commit hashes that introduced the deleted lines.
    """
    introducers: set[str] = set()
    try:
        blame_output = repo.git.blame("-w", f"{parent_hash}^", "--", filepath).split("\n")
    except GitCommandError as exc:
        logging.warning("git blame failed for %s@%s^: %s", filepath, parent_hash, exc.stderr.strip())
        return introducers

    for num_line, line_text in deleted_lines:
        stripped = line_text.strip()
        # Skip comment-only lines and blank lines.
        if not stripped or stripped.startswith("//"):
            continue
        if num_line < 1 or num_line > len(blame_output):
            continue
        blame_parts = blame_output[num_line - 1].split(" ")
        if not blame_parts:
            continue
        raw_hash = blame_parts[0].replace("^", "")
        if raw_hash.startswith("*"):  # unblamable (binary, uncommitted, …)
            continue
        introducers.add(raw_hash)

    return introducers


def get_introduced_date(
    repo_dest_path: str,
    modified_files: pd.DataFrame,
    commit_hash: str,
) -> Optional[pd.Timestamp]:
    """
    Return the earliest committer date among all commits that *introduced*
    the deleted lines in *modified_files* for *commit_hash*.

    Returns None when no introducer commits could be determined.
    """
    repo = Repo(repo_dest_path)
    all_introducers: set[str] = set()

    for _, row in modified_files.iterrows():
        raw = row["diff_parsed"]
        try:
            # Data is stored as Python repr (single-quoted dicts), not JSON.
            diff_parsed = ast.literal_eval(raw)
        except (ValueError, SyntaxError, MemoryError):
            # Fallback: try JSON for rows that may be valid JSON.
            try:
                diff_parsed = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                logging.warning("Skipping unparseable diff_parsed for hash=%s", commit_hash)
                continue

        deleted_lines: list[tuple[int, str]] = diff_parsed.get("deleted", [])
        if not deleted_lines:
            continue

        fname: str = row["old_path"]
        if _should_skip_path(fname):
            continue

        introducers = _blame_introducers(repo, commit_hash, fname, deleted_lines)
        all_introducers |= introducers

    if not all_introducers:
        logging.warning("No buggy commit found for %s", commit_hash)
        return None

    # Earliest committer date among all introducer commits.
    pydriller_repo = PydrillerGit(repo_dest_path)
    earliest: Optional[pd.Timestamp] = None
    for c_hash in all_introducers:
        try:
            commit = pydriller_repo.get_commit(c_hash)
        except Exception:
            logging.debug("Could not retrieve commit %s in %s", c_hash, repo_dest_path)
            continue
        if commit and commit.committer_date:
            if earliest is None or commit.committer_date < earliest:
                earliest = commit.committer_date

    return earliest


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    """Load fix commits from DB, compute fix + introduced dates, write result."""
    logging.info("Loading commits from database …")
    df = pd.read_sql("SELECT cve_id, hash, repo_url FROM commits", con=db.conn)
    df_files = pd.read_sql("SELECT hash, old_path, diff_parsed FROM file_change", con=db.conn)

    n_unique_cves = df["cve_id"].nunique()
    n_unique_hashes = df_files["hash"].nunique()
    n_total = len(df)
    logging.info("CVEs: %d  |  unique file-change hashes: %d  |  total rows: %d",
                 n_unique_cves, n_unique_hashes, n_total)

    fix_dates: list[Optional[pd.Timestamp]] = []
    introduced_dates: list[Optional[pd.Timestamp]] = []
    repo_missing = 0
    commit_retrieved = 0
    commit_not_found = 0
    commit_error = 0

    for _, row in tqdm(df.iterrows(), total=n_total, desc="Processing commits"):
        repo_url: str = row["repo_url"]
        commit_hash: str = row["hash"]
        cve_id = row["cve_id"]

        project_name = get_full_project_name(repo_url)
        repo_path = os.path.join(REPOS_MIRROR, project_name)

        fix_date: Optional[pd.Timestamp] = None
        introduced_date: Optional[pd.Timestamp] = None

        if not os.path.isdir(repo_path) or not is_git_repo(repo_path):
            repo_missing += 1
            fix_dates.append(None)
            introduced_dates.append(None)
            continue

        try:
            commit = PydrillerGit(repo_path).get_commit(commit_hash)
            if commit is None:
                commit_not_found += 1
                fix_dates.append(None)
                introduced_dates.append(None)
                continue
            fix_date = commit.committer_date
            modified_files = df_files[df_files["hash"] == commit_hash]
            introduced_date = get_introduced_date(repo_path, modified_files, commit_hash)
            commit_retrieved += 1
        except Exception:
            logging.exception("Unexpected error processing %s / %s", cve_id, commit_hash)
            commit_error += 1

        fix_dates.append(fix_date)
        introduced_dates.append(introduced_date)

    df["fix_date"] = fix_dates
    df["introduced_date"] = introduced_dates

    logging.info("Writing commit_life_spans table …")
    df.to_sql("commit_life_spans", con=db.conn, if_exists="replace", index=False)

    logging.info(
        "Done.  retrieved=%d  not_found=%d  error=%d  repo_missing=%d",
        commit_retrieved, commit_not_found, commit_error, repo_missing,
    )


if __name__ == "__main__":
    main()
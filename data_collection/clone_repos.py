import logging
import requests
import time
import shutil
import os
import sys
import subprocess
import pandas as pd
from concurrent.futures import ThreadPoolExecutor, as_completed

ROOT_PATH = os.path.dirname(os.path.abspath(__file__))
sys.path.append(f'{ROOT_PATH}/../utils')

import database as db
from utils import get_full_project_name, is_git_repo

# Directory where mirrored repositories are stored
MIRROR_DIR = f"{ROOT_PATH}/../repos_mirror"

import argparse

parser = argparse.ArgumentParser(description="Clone or update vulnerable Rust repositories.")
parser.add_argument(
    "--skip-first-n-repos",
    type=int,
    default=0,
    help="Skip the first N repositories (useful for resuming after interruption).",
)
parser.add_argument(
    "--workers",
    type=int,
    default=4,
    help="Number of parallel clone/fetch workers.",
)
args = parser.parse_args()

skip_first_n_repos = args.skip_first_n_repos
n_workers = args.workers


def run_git_command(command: str) -> subprocess.CompletedProcess:
    """
    Run a git command via subprocess with GIT_ASKPASS and GIT_TERMINAL_PROMPT
    to prevent interactive password prompts.

    Args:
        command: The git command to run.

    Returns:
        subprocess.CompletedProcess with stdout/stderr captured.

    Raises:
        subprocess.CalledProcessError: If the git command exits with non-zero status.
    """
    full_command = f"GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=/bin/false {command}"
    result = subprocess.run(
        full_command,
        shell=True,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
    )
    if result.returncode != 0:
        raise subprocess.CalledProcessError(
            result.returncode, full_command, result.stdout, result.stderr
        )
    return result


def filter_urls(urls):
    """
    Check which URLs are accessible via HTTP HEAD requests.
    Returns URLs that return >= 400 status codes.
    """
    sleeptime = 0
    non_exist_urls = []
    for url in urls:
        print(url)
        code = requests.head(url).status_code
        while code == 429:
            sleeptime += 10
            time.sleep(sleeptime)
            code = requests.head(url).status_code

        if code >= 400:
            non_exist_urls.append(f"{url},{code}")

        sleeptime = 0

    return non_exist_urls


def get_ref_links():
    """
    Retrieve repository URLs from CVE records in the database.
    Filters out inaccessible URLs (currently disabled).
    """
    df_fixes = pd.read_sql("SELECT repo_url FROM cve", con=db.conn)

    print("Checking if references still exist...")
    unique_urls = set(list(df_fixes.repo_url))

    # NOTE: URL accessibility filtering is disabled to avoid rate-limiting.
    # If re-enabled, this would skip repos whose primary URL returns 4xx/5xx.
    # unfetched_urls = filter_urls(unique_urls)
    unfetched_urls = []

    if len(unfetched_urls) > 0:
        logging.debug("The following URLs are not accessible:")
        logging.debug(unfetched_urls)

    # Filter out non-existing repo_urls from the DataFrame
    df_fixes = df_fixes[~df_fixes["repo_url"].isin(unfetched_urls)]

    return df_fixes


def clone_or_update_repo(repo_url: str, repo_dest_path: str):
    """
    Clone a repository as a mirror if it doesn't exist, or update it if it does.

    Args:
        repo_url: Remote URL of the git repository.
        repo_dest_path: Local filesystem path where the mirror should reside.

    Raises:
        Exception: If the clone/fetch operation fails.
    """
    try:
        if os.path.exists(repo_dest_path):
            # Path exists — check if it's a valid git repo
            if is_git_repo(repo_dest_path):
                logging.info("Repository exists. Fetching updates...")
                run_git_command(f"git --git-dir={repo_dest_path} remote update")
                logging.info("Fetching done!")
            else:
                # Path exists but is corrupted or non-git — remove and re-clone
                logging.info(
                    "Path exists but is not a valid git repo. Removing and re-cloning..."
                )
                shutil.rmtree(repo_dest_path)
                clone_cmd = _build_clone_command(repo_url, repo_dest_path)
                run_git_command(clone_cmd)
                logging.info("Cloning done!")
        else:
            # No local copy — clone from remote
            logging.info("Cloning from remote...")
            clone_cmd = _build_clone_command(repo_url, repo_dest_path)
            run_git_command(clone_cmd)
            logging.info("Cloning done!")

    except Exception as e:
        raise e


def _build_clone_command(repo_url: str, repo_dest_path: str) -> str:
    """
    Build a git clone --mirror command string.

    Appends .git suffix if not already present in the URL.
    """
    if ".git" not in repo_url:
        return f"git clone --mirror {repo_url}.git {repo_dest_path}"
    else:
        return f"git clone --mirror {repo_url} {repo_dest_path}"


def handle_url(url: str) -> str:
    """
    Normalize a repository URL to the standard GitHub HTTPS format.

    - Trims extra path segments beyond owner/repo.
    - Strips trailing .git suffix if present.

    For non-GitHub URLs, returns the URL unchanged.
    """
    if "github" in url:
        # Handle URLs that include extra path segments (e.g., /issues, /pull,
        # /tree/main). Keep only the owner/repo part.
        if len(url.split("/")) > 5:
            words = url.split("/")
            url = f"https://github.com/{words[3]}/{words[4]}"
        elif ".git" in url:
            url = url[:-4]  # Strip trailing .git
    return url


def _process_one(repo_url: str) -> bool:
    """
    Clone/update a single repo. Returns True on success, False on failure.

    This is the per-worker unit extracted for parallel execution.
    """
    # ponytail: standalone function avoids per-thread wrapper objects
    full_project_name = get_full_project_name(repo_url)
    if not full_project_name:
        return False

    repo_dest_path = os.path.join(MIRROR_DIR, full_project_name)

    try:
        clone_or_update_repo(repo_url, repo_dest_path)
        return True
    except Exception as e:
        logging.warning(
            f"Problem occurred while retrieving the project: {repo_url}\n {e}"
        )
        return False


def clone_repos(df_fixes: pd.DataFrame):
    """
    Clone or update all repositories listed in the fix commits DataFrame.

    Uses a thread pool to process repos concurrently.

    Args:
        df_fixes: DataFrame containing a 'repo_url' column.
    """
    repo_urls = df_fixes["repo_url"].apply(lambda x: handle_url(x)).unique()

    # Filter non-git URLs and apply skip_first_n
    relevant_urls = [url for url in repo_urls if "git" in url]
    relevant_urls = relevant_urls[skip_first_n_repos:]

    logging.info(
        f"Processing {len(relevant_urls)} repos with {n_workers} workers "
        f"(skipped first {skip_first_n_repos})"
    )

    fail_count = 0
    completed = 0
    total = len(relevant_urls)

    with ThreadPoolExecutor(max_workers=n_workers) as executor:
        futures = {
            executor.submit(_process_one, url): url for url in relevant_urls
        }
        for future in as_completed(futures):
            completed += 1
            url = futures[future]
            ok = future.result()
            if not ok:
                fail_count += 1
            logging.info(f"[{completed}/{total}] {'OK' if ok else 'FAIL'} {url}")

    print(fail_count)


def get_num_vul_has_repo():
    """
    Print statistics about how many vulnerabilities/repos have been cloned.

    Reads from the database and checks local disk for existing mirrors.
    """
    df_master = pd.read_sql("SELECT repo_url, package FROM cve", con=db.conn)

    # Collect URLs whose repos have been successfully cloned locally
    cloned_urls = []
    for url in df_master["repo_url"]:
        # Skip null/empty/string-None entries in the database
        if url is None or url == "None" or url == "":
            continue

        full_project_name = get_full_project_name(handle_url(url))
        if not full_project_name:
            continue

        repo_dest_path = os.path.join(MIRROR_DIR, full_project_name)
        if os.path.exists(repo_dest_path) and is_git_repo(repo_dest_path):
            cloned_urls.append(url)

    packages = df_master["repo_url"].unique()
    print(f"# of Vulnerabilities: {len(df_master)}")
    print(f"# of Vulnerabilities that have repos: {len(cloned_urls)}")
    print(f"# of vulnerable packages: {len(packages)}")
    print(f"# of vulnerable packages that have repos: {len(set(cloned_urls))}")


if __name__ == "__main__":
    clone_repos(get_ref_links())
    get_num_vul_has_repo()

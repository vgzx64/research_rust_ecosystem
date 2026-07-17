#!/usr/bin/env python3
"""
Orchestration script for running unsafe analysis using rust-analyzer.
Replaces compile.py + compile_single.sh with a single script that uses
the new unsafe_analysis_ra binary.

Usage:
    python analyze_project.py <datafile>

The datafile should be a CSV with columns: hash, repo_url, cve_id
"""

import pandas as pd
from pydriller import Git
import sys
import os
import logging
import click

sys.path.append('../../utils')
from utils import get_full_project_name, is_git_repo

dest = "../../repos_mirror"
dest_work = "../../repos_worktree"
analysis_result = "../../compiler_result_v3"
analyze_script = os.path.join(os.path.dirname(__file__), "analyze_single.sh")
check_head = os.path.join(os.path.dirname(__file__), "check_head.sh")
worktree = os.path.join(os.path.dirname(__file__), "worktree.sh")


def get_worktree(repo_dest_path, work_tree_path):
    if not os.path.exists(work_tree_path):
        if os.system(worktree + " " + repo_dest_path + " " + work_tree_path):
            print(repo_dest_path)


@click.command()
@click.argument("datafile", type=click.File("r+"))
def main(datafile):
    df_fixes = pd.read_csv(datafile)
    df_fixes.drop_duplicates(subset=['hash', 'repo_url'], keep='first', inplace=True)

    fail_list = []
    success_list = []
    success_cnt = 0
    fail_cnt = 0
    success_cnt_fix = 0
    fail_cnt_fix = 0

    for index, row in df_fixes.iterrows():
        repo_url = row["repo_url"]
        id = str(row["cve_id"])
        hash = row["hash"]

        full_project_name = get_full_project_name(repo_url)
        repo_dest_path = os.path.join(dest, full_project_name)
        work_tree_path = os.path.join(dest_work, full_project_name)
        if os.path.exists(repo_dest_path):
            if is_git_repo(repo_dest_path):
                try:
                    commit = Git(repo_dest_path).get_commit(hash)
                    get_worktree(repo_dest_path, work_tree_path)

                    # Analyze vulnerable version (before fix)
                    analysis_dir = f"{analysis_result}/{full_project_name}/{id}/{hash}"
                    if not os.path.exists(analysis_dir):
                        print("git check ", commit.parents[0])
                        cmd_gc = check_head + " " + work_tree_path + " " + commit.parents[0]
                        os.system(cmd_gc)
                        # Run the analysis script
                        if os.system(analyze_script + " " + work_tree_path + " " + id + " " + commit.parents[0] + " " + analysis_dir) == 0:
                            success_cnt += 1
                            success_list.append(full_project_name)
                        else:
                            os.system(f"rm -rf {analysis_dir}")
                            fail_cnt += 1
                            fail_list.append(full_project_name)

                        print("success_cnt =", success_cnt)
                        print("total =", success_cnt + fail_cnt)
                    else:
                        print("{}: Vulnerability existing already analyzed!".format(id))
                        success_list.append(full_project_name)
                        success_cnt += 1

                    # Analyze fixed version (after fix)
                    analysis_dir = f"{analysis_result}/{full_project_name}/{id}_fix/{hash}"
                    if not os.path.exists(analysis_dir):
                        print("git check ", commit.hash)
                        os.system(check_head + " " + work_tree_path + " " + commit.hash)
                        # Run the analysis script
                        if os.system(analyze_script + " " + work_tree_path + " " + id + "_fix" + " " + commit.hash + " " + analysis_dir) == 0:
                            success_cnt_fix += 1
                        else:
                            fail_cnt_fix += 1
                            os.system(f"rm -rf {analysis_dir}")

                        print("success_cnt_fix =", success_cnt_fix)
                        print("total =", fail_cnt_fix + success_cnt_fix)
                    else:
                        print("{}: Vulnerability fixing commit already analyzed!".format(id))
                        success_cnt_fix += 1

                except Exception as e:
                    logging.warning('Problem while fetching the commits!')
                    print(e)
                    pass

            else:
                logging.warning('Repos not cloned!')
    print("success: ", success_cnt)
    print("fail: ", fail_cnt)
    print("success_fix: ", success_cnt_fix)
    print("fail_fix: ", fail_cnt_fix)

    with open("fail", "w") as f:
        for l in fail_list:
            f.write(l + "\n")

    with open("success", "w") as f:
        for l in success_list:
            f.write(l + "\n")


if __name__ == '__main__':
    main()
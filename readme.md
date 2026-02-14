# Extended Research
**Reproduce the results**:

- Requirements:

```
Python 3.13
pandas 2.3.3
other packages listed in requirements.txt
```

- Run the following commands:

```shell
sudo apt install python3-pip
sudo apt install python3-virtualenv
virtualenv -p /usr/bin/python3 test-env
source test-env/bin/activate
pip3 install -r requirements.txt
```

- Follow steps in the jupter files in `RQ\`  to get the statistics and figures. Generated figs are inside`RQ\fig`.

**Collect the dataset**:

1. **Data Collection** (`data_collection/`)
   - `collect_vuls.ipynb`: collect vulnerabilities and package metadata.
   - `clone_repos.py`: clone vulnerable package repositories in a specific directory.

2. **Data Extraction** (`data_extraction/`)
   - `collect_commits.ipynb`: Mine vulnerability-fix commits.
   - `extract_changes.py`: Extract changes in fix commits.
   - `extract_life_span.py`: Extract commit date of introduced commits and fix commits.
3. **Source code Analysis** (`source_analysis/`)
   - `compile.py`: Get the location of unsafe/safe functions and blocks in vulnerable packages by using Rust compiler plugin.
   -  `format_result.py`: Format compilation results into database.
   - `regex.py`: Parse total safe/unsafe count

# Research Questions — Agent Guide

## Purpose
Jupyter notebooks that analyze the collected data to answer the four research questions in the paper. These notebooks consume data from the MySQL database and produce statistical results and figures.

## Directory Structure

```
RQ/
├── RQ1.ipynb  — Vulnerability characteristics and distributions
├── RQ2.ipynb  — Unsafe code prevalence and vulnerability locality
├── RQ3.ipynb  — Statistical analysis and comparisons
└── fig/       — Generated figures
    ├── rq1/   — Figures for RQ1
    └── rq2/   — Figures for RQ2
```

## Notebooks

### RQ1.ipynb — Vulnerability Characteristics
- **What it analyzes**: Basic statistics about the dataset
- **Data consumed from DB**: `cve` table (vulnerability metadata)
- **Key analyses**:
  - Number of vulnerabilities, packages, and versions affected
  - Distribution of vulnerability types (SFP → category mapping)
  - Vulnerability severity distribution (CVSS scores)
  - Packages with most vulnerabilities
  - Affected version percentages per package
  - Vulnerability lifespan (time to disclosure, time to fix)
- **Outputs**: Summary statistics printed in notebook

### RQ2.ipynb — Unsafe Code Prevalence
- **What it analyzes**: How much unsafe code exists in vulnerable vs. non-vulnerable contexts
- **Data consumed from DB**:
  - `vul_safe_unsafe` table — per-vulnerability unsafe counts
  - `total_safe_unsafe` + `total_safe_unsafe_regex` — aggregate counts
  - `ext_commits` — commit metadata (file counts)
  - `cve` — vulnerability metadata for SFp categorization
  - `categories`, `crates_categories`, `crates` — package category metadata
- **Key analyses**:
  - Local file, safe function, unsafe function, and block counts per vulnerability
  - Vulnerability locality across SFP categories
  - Ratio of unsafe functions/blocks (violin plots comparing vulnerable code vs. all code)
  - Wilcoxon signed-rank test comparing vulnerable vs. all code
- **Outputs**: Figures in `fig/rq2/` and statistical test results

### RQ3.ipynb — Statistical Analysis
- **What it analyzes**: Statistical comparisons between vulnerability types
- **Data consumed from DB**: Same as RQ2, primarily `vul_safe_unsafe` and `cve` tables
- **Key analyses**:
  - Statistical tests across SFP categories
  - Comparison of unsafe code ratios across different vulnerability types
- **Outputs**: Statistical test results

## Database Tables Consumed

| Table | Used By | Purpose |
|-------|---------|---------|
| `cve` | RQ1, RQ2, RQ3 | Vulnerability metadata, SFP IDs |
| `vul_safe_unsafe` | RQ2, RQ3 | Vulnerability-to-unsafe-code mapping |
| `total_safe_unsafe` | RQ2 | Aggregate safe/unsafe counts |
| `total_safe_unsafe_regex` | RQ2 | Regex fallback counts |
| `ext_commits` | RQ2 | Commit metadata |
| `categories` | RQ2 | Crate categories |
| `crates_categories` | RQ2 | Crate-category mapping |
| `crates` | RQ2 | Crate metadata |
| `versions` | RQ1 | Version history |

## How to Run

```bash
cd RQ
jupyter notebook RQ1.ipynb
# or
jupyter nbconvert --to notebook --execute RQ1.ipynb
```

## Dependencies
- All notebooks require database connection (via `utils/database.py`)
- Additional Python packages: matplotlib, seaborn, scipy, scikit-posthocs, statsmodels
- Virtual environment should be activated: `.venv/` or `.venv-3.13/`
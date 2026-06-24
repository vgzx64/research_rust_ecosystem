import re
from git import Repo, exc
import matplotlib.pyplot as plt
import matplotlib.dates as mdates

# Shared regex: matches any known git hosting URL and captures owner/project
# Covers: github, gitlab, bitbucket, codeberg, sr.ht, gitee, and self-hosted variants
_GIT_URL_RE = re.compile(
    r'https?://(?:[a-zA-Z0-9-]+\.)*(?:bitbucket|github|gitlab|git|gitee|sr\.ht|torproject|gnome|redox-os)'
    r'(?:\.[a-zA-Z0-9-]+)+'
    r'/(?P<owner>[^/#?]+)/(?P<project>[^/#?]+?)(?:\.git)?(?:/|$)',
    re.IGNORECASE,
)


def parse_git_url(url):
    """
    Extract (owner, project) from a git hosting URL.

    Returns (owner, project) on success, or (None, None) if the URL
    doesn't match a known git hosting service pattern.

    >>> parse_git_url("https://github.com/apollographql/router.git")
    ('apollographql', 'router')
    >>> parse_git_url("https://github.com/apollographql/router/")
    ('apollographql', 'router')
    """
    if not url or url in ('', 'None'):
        return None, None
    m = _GIT_URL_RE.search(url)
    if m:
        return m.group('owner'), m.group('project')
    return None, None


def adjust_message(message):
    message_no_carriage = message.replace("\r", "\n")
    one_newline_message = re.sub(r"\n+", "\n", message_no_carriage)
    clear_message = one_newline_message.replace("\n", ". ").replace("\t", " ").replace(",", " ").replace("\"", "'")
    stripped_message = clear_message.strip()
    return re.sub(r" +", " ", stripped_message)


def get_full_project_name(repo_url):
    if repo_url is None or repo_url == '' or repo_url == 'None':
        return ''
    owner, project = parse_git_url(repo_url)
    if owner and project:
        return owner + "_" + project
    # Fallback: rsplit-based attempt for unrecognised formats
    parts = repo_url.rsplit('/', 2)
    if len(parts) < 3:
        return ''
    return parts[1] + "_" + parts[2].replace('.git', '')


def is_git_repo(path):
    try:
        _ = Repo(path).git_dir
        return True
    except exc.InvalidGitRepositoryError:
        return False
    
def plot_evolution(x, y, ylabel, savepath, evol=True, xlog=False, ylog=False):
    plt.ioff()
    plt.style.use('seaborn-v0_8-colorblind') 
    fig, ax = plt.subplots(1, 1, figsize=(15, 10))
    ax.plot(x, y,color='navy')
    ax.set(ylabel=ylabel)
    ax.tick_params(labelsize=25)
    ax.yaxis.label.set_size(25)
    ax.title.set_size(20)
    if evol:
        # Use YearLocator to ensure ticks at the start of each year
        ax.xaxis.set_major_locator(mdates.YearLocator())
        ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y'))
        ax.xaxis.set_minor_locator(mdates.MonthLocator())
        fig.autofmt_xdate()
        
        # Ensure the last year is included in the x-axis range
        if len(x) > 0:
            # Add small padding to ensure last year label appears
            from pandas.tseries.offsets import DateOffset
            x_min = x[0]
            x_max = x[-1] + DateOffset(months=1)
            ax.set_xlim(x_min, x_max)
    if xlog:
        ax.set_xscale('symlog')
    ax.grid(True, linestyle='--', which="major")
    fig.savefig(savepath, facecolor='white', dpi=200) 

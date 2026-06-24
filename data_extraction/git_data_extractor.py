import requests
import json
import re
import os
from urllib.parse import urlparse
from datetime import datetime

class GitDataExtractor:
    def __init__(self, url, tokens):
        """
        Args:
            url (str): The URL of the Issue or PR.
            tokens (dict): A dictionary of tokens keyed by provider domain.
                           Example: {'github.com': 'ghp_...', 'gitlab.com': 'glpat-...'}
        """
        self.url = url
        self.tokens = tokens
        self.token = None  # Will be set after domain detection
        
        self.engine = None
        self.domain = None
        self.repo_owner = None
        self.repo_name = None
        self.repo_url = None
        self.is_pr = False
        self.data_identifier = None
        
        # Initialize
        self._parse_url_metadata()
        
        # Assign token based on detected domain
        # We check for exact match first, then partial match for self-hosted instances
        self.token = self._get_token_for_domain()

    def _get_token_for_domain(self):
        """Finds the appropriate token from the dict, handling generic and specific domains."""
        # 1. Try exact match (e.g. "github.com")
        if self.domain in self.tokens:
            return self.tokens[self.domain]
            
        # 2. Try partial match for self-hosted instances (e.g. "gitlab.redox-os.org")
        # Checks if any key in the dict is part of the detected domain
        for key, value in self.tokens.items():
            if key in self.domain:
                return value

        raise Exception(f"No token found for {self.domain}")

    def _parse_url_metadata(self):
        """Extracts repo and engine info from the URL."""
        parsed = urlparse(self.url)
        self.domain = parsed.netloc.lower()
        path_parts = parsed.path.strip('/').split('/')

        # Determine Engine and basic structure
        if 'github.com' in self.domain:
            self.engine = 'github'
            # owner/repo/issues/123 OR owner/repo/pull/123
            if len(path_parts) < 4: raise ValueError("Invalid GitHub URL")
            self.repo_owner = path_parts[0]
            self.repo_name = path_parts[1]
            type_str = path_parts[2]
            self.data_identifier = int(path_parts[3]) if path_parts[3].isnumeric() else path_parts[3]
            self.is_pr = (type_str == 'pull')
            self.is_commit = (type_str == 'commit')

        elif 'gitlab' in self.domain:
            self.engine = 'gitlab'
            # owner/repo/-/issues/123 OR owner/repo/-/merge_requests/123
            # Regex is safer for GitLab due to possible sub-groups
            match = re.search(r'gitlab\..*?/(.*?)/(.*?)/-/(issues|merge_requests|commit)/(\d+)', self.url)
            if not match: raise ValueError("Invalid GitLab URL")
            self.repo_owner = match.group(1)
            self.repo_name = match.group(2)
            self.is_pr = (match.group(3) == 'merge_requests')
            self.is_commit = (match.group(3) == 'commit')
            self.data_identifier = int(match.group(4))

        elif 'bitbucket.org' in self.domain:
            self.engine = 'bitbucket'
            # workspace/repo/issues/123
            if len(path_parts) < 4: raise ValueError("Invalid Bitbucket URL")
            self.repo_owner = path_parts[0]
            self.repo_name = path_parts[1]
            type_str = path_parts[2]
            self.data_identifier = int(path_parts[3])
            self.is_pr = (type_str == 'pullrequests') # Bitbucket uses pullrequests

        elif 'codeberg.org' in self.domain:
            self.engine = 'forgejo' # Codeberg runs Forgejo
            # owner/repo/issues/123
            if len(path_parts) < 4: raise ValueError("Invalid Codeberg URL")
            self.repo_owner = path_parts[0]
            self.repo_name = path_parts[1]
            self.is_pr = (path_parts[2] == 'pulls') # Codeberg uses /pulls
            self.data_identifier = int(path_parts[3])

        elif 'sr.ht' in self.domain:
            self.engine = 'sourcehut'
            # ~user/repo/123
            if len(path_parts) < 3: raise ValueError("Invalid sr.ht URL")
            self.repo_owner = path_parts[0].replace('~', '') # Strip tilde
            self.repo_name = path_parts[1]
            self.data_identifier = int(path_parts[2])
            # sr.ht URLs usually don't have /issues/ or /pulls/ in the path for standard tickets,
            # they are often just under the repo or a specific tracker. 
            # We will treat everything as an 'issue' unless we detect 'pullrequest' explicitly, 
            # though sr.ht separates them differently.
            self.is_pr = False 

        else:
            raise ValueError(f"Unsupported platform: {self.domain}")

        # Construct the repo URL (Clonable/Web Base)
        self.repo_url = f"{parsed.scheme}://{self.domain}/{self.repo_owner}/{self.repo_name}"

    def extract(self):
        """Dispatch to specific fetcher or load from cache."""
        cache_path = self._get_cache_path()
        
        # Check if cache exists
        if os.path.exists(os.path.join(cache_path, "main.json")):
            return self._load_from_cache(cache_path)
        
        issue = None
        activity = None
        
        if self.engine == 'github':
            issue, activity = self._fetch_github()
        elif self.engine == 'gitlab':
            issue, activity = self._fetch_gitlab()
        elif self.engine == 'bitbucket':
            issue, activity = self._fetch_bitbucket()
        elif self.engine == 'forgejo':
            issue, activity = self._fetch_forgejo()
        elif self.engine == 'sourcehut':
            issue, activity = self._fetch_srht()
        else:
            return None, None

        # Save to cache if successful
        if issue is not None:
            self._save_to_cache(cache_path, issue, activity)
            
        return issue, activity

    # --- GitHub (REST only) ---
    def _fetch_github(self):
        """
        Fetches issue/PR metadata and timeline entirely via GitHub REST API.
        """
        headers = {"Authorization": f"Bearer {self.token}"}

        # 1. Fetch issue/PR metadata via REST
        issue = self._fetch_github_issue(headers)

        # 2. If it's a PR, merge in PR-specific fields
        if self.is_pr:
            pr_data = self._fetch_github_pr(headers)
            if pr_data:
                issue.update(pr_data)

        # 3. Fetch timeline activity via REST /timeline endpoint
        activity = self._fetch_github_timeline(headers)

        return issue, activity

    def _fetch_github_issue(self, headers):
        """Fetches issue metadata via GET /repos/{owner}/{repo}/issues/{number}."""
        url = f"https://api.github.com/repos/{self.repo_owner}/{self.repo_name}/issues/{self.data_identifier}"
        resp = requests.get(url, headers=headers)
        if resp.status_code != 200:
            raise Exception(f"GitHub API Error: {resp.status_code} {resp.text[:200]}")
        data = resp.json()

        # Map REST field names to what to_markdown expects
        labels = []
        for lbl in data.get('labels', []):
            if isinstance(lbl, dict):
                labels.append({'name': lbl.get('name', ''), 'color': lbl.get('color', '')})

        milestone = data.get('milestone')
        milestone_title = milestone.get('title') if isinstance(milestone, dict) else None

        return {
            'number': data.get('number'),
            'title': data.get('title', ''),
            'state': data.get('state', ''),
            'author': {'login': data.get('user', {}).get('login', '')},
            'body': data.get('body', ''),
            'createdAt': data.get('created_at', ''),
            'updatedAt': data.get('updated_at', ''),
            'closedAt': data.get('closed_at'),
            'labels': {'nodes': labels},
            'milestone': {'title': milestone_title} if milestone_title else None,
            'url': data.get('html_url', ''),
        }

    def _fetch_github_pr(self, headers):
        """Fetches PR-specific metadata via GET /repos/{owner}/{repo}/pulls/{number}."""
        url = f"https://api.github.com/repos/{self.repo_owner}/{self.repo_name}/pulls/{self.data_identifier}"
        resp = requests.get(url, headers=headers)
        if resp.status_code != 200:
            return {}
        data = resp.json()

        merged_by = data.get('merged_by')
        return {
            'mergedAt': data.get('merged_at'),
            'mergedBy': {'login': merged_by.get('login')} if merged_by else None,
            'baseRefName': data.get('base', {}).get('ref', ''),
            'headRefName': data.get('head', {}).get('ref', ''),
            'additions': data.get('additions'),
            'deletions': data.get('deletions'),
            'changedFiles': data.get('changed_files'),
        }

    def _fetch_github_timeline(self, headers):
        """
        Fetches all timeline events via GET /repos/{owner}/{repo}/issues/{number}/timeline.
        This endpoint reliably includes cross-referenced events (unlike /events).
        """
        try:
            url = f"https://api.github.com/repos/{self.repo_owner}/{self.repo_name}/issues/{self.data_identifier}/timeline"
            response = requests.get(url, headers=headers, params={"per_page": 100})
            if response.status_code != 200:
                return []

            events = response.json()
            mapped_events = []

            for event in events:
                if not isinstance(event, dict):
                    continue

                event_type = event.get('event', '')
                event_id = event.get('id')
                if not event_type or not event_id:
                    continue

                mapped = {
                    'id': event_id,
                    '__typename': event_type,
                    'createdAt': event.get('created_at'),
                    'actor': {'login': event.get('actor', {}).get('login')} if event.get('actor') else None,
                }

                # For 'commented' events, extract the comment body and author
                if event_type == 'commented':
                    mapped['body'] = event.get('body', '')
                    mapped['author'] = {'login': event.get('user', {}).get('login', '')} if event.get('user') else None

                elif event_type == 'cross-referenced':
                    source = event.get('source', {})
                    issue_ref = source.get('issue', {})
                    if issue_ref:
                        mapped['source'] = {
                            'number': issue_ref.get('number'),
                            'url': issue_ref.get('html_url'),
                            'title': issue_ref.get('title'),
                            'state': issue_ref.get('state'),
                            'repository': {
                                'nameWithOwner': issue_ref.get('repository_url', '').replace('https://api.github.com/repos/', '')
                            }
                        }
                        if issue_ref.get('pull_request'):
                            mapped['source']['__typename'] = 'PullRequest'
                        else:
                            mapped['source']['__typename'] = 'Issue'

                elif event_type == 'referenced':
                    commit = event.get('commit_id', '')
                    if commit:
                        mapped['commit'] = {
                            'oid': commit,
                            'url': f"https://github.com/{self.repo_owner}/{self.repo_name}/commit/{commit}"
                        }

                elif event_type == 'labeled':
                    label = event.get('label', {})
                    mapped['label'] = {'name': label.get('name'), 'color': label.get('color')}

                elif event_type == 'unlabeled':
                    label = event.get('label', {})
                    mapped['label'] = {'name': label.get('name'), 'color': label.get('color')}

                elif event_type == 'assigned':
                    assignee = event.get('assignee', {})
                    mapped['assignee'] = {'login': assignee.get('login')} if assignee else None

                elif event_type == 'renamed':
                    mapped['previousTitle'] = event.get('rename', {}).get('from')
                    mapped['currentTitle'] = event.get('rename', {}).get('to')

                elif event_type == 'milestoned':
                    mapped['milestoneTitle'] = event.get('milestone', {}).get('title')

                elif event_type == 'demilestoned':
                    mapped['milestoneTitle'] = event.get('milestone', {}).get('title')

                mapped_events.append(mapped)

            return mapped_events

        except Exception as e:
            print(f"Error fetching REST timeline for {self.url}: {e}")
            return []

    def to_markdown(self, issue_data=None, activity_data=None):
        """
        Renders the issue/PR data as a markdown document, similar to what you'd see
        on the web version of GitHub.

        Args:
            issue_data (dict, optional): Issue/PR data from extract(). If None, fetches it.
            activity_data (list, optional): Timeline/activity data from extract().

        Returns:
            str: Markdown representation of the issue/PR.
        """
        if issue_data is None:
            issue_data, activity_data = self.extract()
            if issue_data is None:
                return f"# Error: Could not fetch data for {self.url}"

        lines = []
        is_pr = issue_data.get('__typename') == 'PullRequest' or self.is_pr

        # --- Header ---
        item_type = "Pull Request" if is_pr else "Issue"
        number = issue_data.get('number', self.data_identifier)
        title = issue_data.get('title', '')
        state = issue_data.get('state', 'unknown')
        state_icon = "✅" if state == 'closed' else "🟢" if state == 'open' else "❓"
        lines.append(f"# {state_icon} {title}")
        lines.append(f"**{item_type} #{number}** · {self.repo_owner}/{self.repo_name}")
        lines.append("")

        # --- Metadata ---
        author = issue_data.get('author', {})
        if isinstance(author, dict):
            author_login = author.get('login', 'unknown')
        else:
            author_login = str(author)
        created_at = issue_data.get('createdAt', '')
        updated_at = issue_data.get('updatedAt', '')
        closed_at = issue_data.get('closedAt', '')

        lines.append(f"**Author:** @{author_login}")
        if created_at:
            lines.append(f"**Created:** {created_at}")
        if updated_at:
            lines.append(f"**Updated:** {updated_at}")
        if closed_at:
            lines.append(f"**Closed:** {closed_at}")

        # PR-specific metadata
        if is_pr:
            merged_at = issue_data.get('mergedAt', '')
            merged_by = issue_data.get('mergedBy', {})
            if merged_at:
                merged_by_login = merged_by.get('login', 'unknown') if isinstance(merged_by, dict) else 'unknown'
                lines.append(f"**Merged:** {merged_at} by @{merged_by_login}")
            lines.append(f"**Branch:** {issue_data.get('baseRefName', '?')} ← {issue_data.get('headRefName', '?')}")
            additions = issue_data.get('additions')
            deletions = issue_data.get('deletions')
            changed_files = issue_data.get('changedFiles')
            if additions is not None:
                lines.append(f"**Changes:** +{additions}/-{deletions} in {changed_files} files")

        # Labels
        labels = issue_data.get('labels', {})
        label_nodes = labels.get('nodes', []) if isinstance(labels, dict) else []
        if label_nodes:
            label_strs = []
            for lbl in label_nodes:
                if isinstance(lbl, dict):
                    name = lbl.get('name', '')
                    color = lbl.get('color', '')
                    if name:
                        label_strs.append(f"`{name}`")
            if label_strs:
                lines.append(f"**Labels:** {' '.join(label_strs)}")

        # Milestone
        milestone = issue_data.get('milestone', {})
        if isinstance(milestone, dict) and milestone.get('title'):
            lines.append(f"**Milestone:** {milestone['title']}")

        lines.append("")
        lines.append("---")
        lines.append("")

        # --- Body ---
        body = issue_data.get('body', '')
        if body and body.strip():
            lines.append(body)
        else:
            lines.append("*No description provided.*")
        lines.append("")
        lines.append("---")
        lines.append("")

        # --- Timeline / Activity ---
        if activity_data:
            lines.append("## Activity")
            lines.append("")

            for item in activity_data:
                if not isinstance(item, dict):
                    continue

                typename = item.get('__typename', '')
                created_at = item.get('createdAt', '')
                actor = item.get('actor', {})
                if isinstance(actor, dict):
                    actor_login = actor.get('login', '')
                else:
                    actor_login = ''

                # Format timestamp
                ts = ""
                if created_at:
                    try:
                        dt = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                        ts = dt.strftime('%Y-%m-%d %H:%M UTC')
                    except (ValueError, AttributeError):
                        ts = created_at

                # Map REST event type strings to GraphQL-style names for rendering
                # REST API returns lowercase event types (e.g. 'commented', 'cross-referenced')
                # while GraphQL returns PascalCase (e.g. 'IssueComment', 'CrossReferencedEvent')
                rest_type_map = {
                    'commented': 'IssueComment',
                    'cross-referenced': 'CrossReferencedEvent',
                    'referenced': 'ReferencedEvent',
                    'labeled': 'LabeledEvent',
                    'unlabeled': 'UnlabeledEvent',
                    'assigned': 'AssignedEvent',
                    'unassigned': 'UnassignedEvent',
                    'closed': 'ClosedEvent',
                    'reopened': 'ReopenedEvent',
                    'merged': 'MergedEvent',
                    'renamed': 'RenamedTitleEvent',
                    'milestoned': 'MilestonedEvent',
                    'demilestoned': 'DemilestonedEvent',
                    'head_ref_deleted': 'HeadRefDeletedEvent',
                    'head_ref_restored': 'HeadRefRestoredEvent',
                    'ready_for_review': 'ReadyForReviewEvent',
                    'converted_to_draft': 'ConvertToDraftEvent',
                    'review_requested': 'ReviewRequestedEvent',
                    'review_request_removed': 'ReviewRequestRemovedEvent',
                    'locked': 'LockedEvent',
                    'unlocked': 'UnlockedEvent',
                    'auto_merge_enabled': 'AutoMergeEnabledEvent',
                    'auto_merge_disabled': 'AutoMergeDisabledEvent',
                    'base_ref_changed': 'BaseRefChangedEvent',
                    'base_ref_force_pushed': 'BaseRefForcePushedEvent',
                    'review_dismissed': 'ReviewDismissedEvent',
                    'comment_deleted': 'CommentDeletedEvent',
                    'marked_as_duplicate': 'MarkedAsDuplicateEvent',
                    'unmarked_as_duplicate': 'UnmarkedAsDuplicateEvent',
                    'pinned': 'PinnedEvent',
                    'unpinned': 'UnpinnedEvent',
                    'subscribed': 'SubscribedEvent',
                    'unsubscribed': 'UnsubscribedEvent',
                    'transferred': 'TransferredEvent',
                    'connected': 'ConnectedEvent',
                    'disconnected': 'DisconnectedEvent',
                    'deployed': 'DeployedEvent',
                    'deployment_environment_changed': 'DeploymentEnvironmentChangedEvent',
                    'added_to_project': 'AddedToProjectEvent',
                    'removed_from_project': 'RemovedFromProjectEvent',
                    'moved_columns_in_project': 'MovedColumnsInProjectEvent',
                    'converted_note_to_issue': 'ConvertedNoteToIssueEvent',
                    'user_blocked': 'UserBlockedEvent',
                }
                # Map REST event type to GraphQL typename for rendering
                if typename in rest_type_map:
                    typename = rest_type_map[typename]

                if typename == 'IssueComment':
                    author_comment = item.get('author', {})
                    if isinstance(author_comment, dict):
                        comment_author = author_comment.get('login', 'unknown')
                    else:
                        comment_author = str(author_comment)
                    body_text = item.get('body', '')
                    lines.append(f"### 💬 Comment by @{comment_author} — {ts}")
                    lines.append("")
                    if body_text:
                        lines.append(body_text)
                    else:
                        lines.append("*No content*")
                    lines.append("")
                    lines.append("---")
                    lines.append("")

                elif typename == 'ReferencedEvent':
                    commit = item.get('commit', {})
                    if isinstance(commit, dict):
                        oid = commit.get('oid', '')
                        commit_url = commit.get('url', '')
                        commit_msg = commit.get('message', '')
                        short_oid = oid[:7] if oid else '?'
                        if commit_url:
                            lines.append(f"### 🔗 Referenced commit [{short_oid}]({commit_url}) by @{actor_login} — {ts}")
                        else:
                            lines.append(f"### 🔗 Referenced commit `{short_oid}` by @{actor_login} — {ts}")
                        if commit_msg:
                            first_line = commit_msg.split('\n')[0]
                            lines.append(f"> {first_line}")
                    lines.append("")
                    lines.append("---")
                    lines.append("")

                elif typename == 'CrossReferencedEvent':
                    source = item.get('source', {})
                    if isinstance(source, dict):
                        source_url = source.get('url', '')
                        source_num = source.get('number', '?')
                        source_title = source.get('title', '')
                        source_state = source.get('state', '')
                        source_repo = source.get('repository', {})
                        if isinstance(source_repo, dict):
                            repo_name = source_repo.get('nameWithOwner', '')
                        else:
                            repo_name = ''
                        source_type = source.get('__typename', 'Issue')

                        icon = "🔀" if source_type == 'PullRequest' else "📌"
                        state_icon = "✅" if source_state == 'closed' else "🟢" if source_state == 'open' else ""

                        if source_url:
                            lines.append(f"### {icon} Cross-referenced by [{repo_name}#{source_num}]({source_url}) — {ts}")
                        else:
                            lines.append(f"### {icon} Cross-referenced by {repo_name}#{source_num} — {ts}")
                        if source_title:
                            lines.append(f"> {state_icon} {source_title}")
                    lines.append("")
                    lines.append("---")
                    lines.append("")

                elif typename == 'LabeledEvent':
                    label = item.get('label', {})
                    if isinstance(label, dict):
                        label_name = label.get('name', '')
                        lines.append(f"### 🏷️ Added **{label_name}** by @{actor_login} — {ts}")
                    lines.append("")
                    lines.append("---")
                    lines.append("")

                elif typename == 'UnlabeledEvent':
                    label = item.get('label', {})
                    if isinstance(label, dict):
                        label_name = label.get('name', '')
                        lines.append(f"### 🏷️ Removed **{label_name}** by @{actor_login} — {ts}")
                    lines.append("")
                    lines.append("---")
                    lines.append("")

                elif typename == 'AssignedEvent':
                    assignee = item.get('assignee', {})
                    if isinstance(assignee, dict):
                        assignee_login = assignee.get('login', '')
                        lines.append(f"### 👤 Assigned @{assignee_login} by @{actor_login} — {ts}")
                    lines.append("")
                    lines.append("---")
                    lines.append("")

                elif typename == 'UnassignedEvent':
                    assignee = item.get('assignee', {})
                    if isinstance(assignee, dict):
                        assignee_login = assignee.get('login', '')
                        lines.append(f"### 👤 Unassigned @{assignee_login} by @{actor_login} — {ts}")
                    lines.append("")
                    lines.append("---")
                    lines.append("")

                elif typename == 'ClosedEvent':
                    lines.append(f"### ❌ Closed by @{actor_login} — {ts}")
                    lines.append("")
                    lines.append("---")
                    lines.append("")

                elif typename == 'ReopenedEvent':
                    lines.append(f"### 🔄 Reopened by @{actor_login} — {ts}")
                    lines.append("")
                    lines.append("---")
                    lines.append("")

                elif typename == 'MergedEvent':
                    commit = item.get('commit', {})
                    if isinstance(commit, dict):
                        oid = commit.get('oid', '')
                        commit_url = commit.get('url', '')
                        short_oid = oid[:7] if oid else '?'
                        if commit_url:
                            lines.append(f"### ✅ Merged commit [{short_oid}]({commit_url}) by @{actor_login} — {ts}")
                        else:
                            lines.append(f"### ✅ Merged by @{actor_login} — {ts}")
                    else:
                        lines.append(f"### ✅ Merged by @{actor_login} — {ts}")
                    lines.append("")
                    lines.append("---")
                    lines.append("")

                elif typename == 'RenamedTitleEvent':
                    prev = item.get('previousTitle', '')
                    curr = item.get('currentTitle', '')
                    lines.append(f"### ✏️ Title changed by @{actor_login} — {ts}")
                    lines.append(f"> ~~{prev}~~ → **{curr}**")
                    lines.append("")
                    lines.append("---")
                    lines.append("")

                elif typename == 'MilestonedEvent':
                    ms_title = item.get('milestoneTitle', '')
                    lines.append(f"### 🎯 Added to milestone **{ms_title}** by @{actor_login} — {ts}")
                    lines.append("")
                    lines.append("---")
                    lines.append("")

                elif typename == 'DemilestonedEvent':
                    ms_title = item.get('milestoneTitle', '')
                    lines.append(f"### 🎯 Removed from milestone **{ms_title}** by @{actor_login} — {ts}")
                    lines.append("")
                    lines.append("---")
                    lines.append("")

                elif typename == 'HeadRefDeletedEvent':
                    lines.append(f"### 🗑️ Branch deleted by @{actor_login} — {ts}")
                    lines.append("")
                    lines.append("---")
                    lines.append("")

                elif typename == 'HeadRefRestoredEvent':
                    lines.append(f"### 🔄 Branch restored by @{actor_login} — {ts}")
                    lines.append("")
                    lines.append("---")
                    lines.append("")

                elif typename == 'ReadyForReviewEvent':
                    lines.append(f"### 👀 Ready for review by @{actor_login} — {ts}")
                    lines.append("")
                    lines.append("---")
                    lines.append("")

                elif typename == 'ConvertToDraftEvent':
                    lines.append(f"### 📝 Converted to draft by @{actor_login} — {ts}")
                    lines.append("")
                    lines.append("---")
                    lines.append("")

                elif typename == 'ReviewRequestedEvent':
                    lines.append(f"### 👀 Review requested by @{actor_login} — {ts}")
                    lines.append("")
                    lines.append("---")
                    lines.append("")

                elif typename == 'ReviewRequestRemovedEvent':
                    lines.append(f"### 👀 Review request removed by @{actor_login} — {ts}")
                    lines.append("")
                    lines.append("---")
                    lines.append("")

                elif typename == 'LockedEvent':
                    lines.append(f"### 🔒 Locked by @{actor_login} — {ts}")
                    lines.append("")
                    lines.append("---")
                    lines.append("")

                elif typename == 'UnlockedEvent':
                    lines.append(f"### 🔓 Unlocked by @{actor_login} — {ts}")
                    lines.append("")
                    lines.append("---")
                    lines.append("")

                elif typename == 'AutoMergeEnabledEvent':
                    lines.append(f"### 🤖 Auto-merge enabled by @{actor_login} — {ts}")
                    lines.append("")
                    lines.append("---")
                    lines.append("")

                elif typename == 'AutoMergeDisabledEvent':
                    lines.append(f"### 🤖 Auto-merge disabled by @{actor_login} — {ts}")
                    lines.append("")
                    lines.append("---")
                    lines.append("")

                elif typename == 'PullRequestCommit':
                    commit = item.get('commit', {})
                    if isinstance(commit, dict):
                        oid = commit.get('oid', '')
                        commit_url = commit.get('url', '')
                        commit_msg = commit.get('message', '')
                        short_oid = commit.get('abbreviatedOid', oid[:7] if oid else '?')
                        if commit_url:
                            lines.append(f"### 📦 Commit [{short_oid}]({commit_url}) — {ts}")
                        else:
                            lines.append(f"### 📦 Commit `{short_oid}` — {ts}")
                        if commit_msg:
                            first_line = commit_msg.split('\n')[0]
                            lines.append(f"> {first_line}")
                    lines.append("")
                    lines.append("---")
                    lines.append("")

                elif typename == 'BaseRefChangedEvent':
                    lines.append(f"### 🔄 Base branch changed by @{actor_login} — {ts}")
                    lines.append("")
                    lines.append("---")
                    lines.append("")

                elif typename == 'BaseRefForcePushedEvent':
                    lines.append(f"### ⚡ Base branch force-pushed by @{actor_login} — {ts}")
                    lines.append("")
                    lines.append("---")
                    lines.append("")

                elif typename == 'ReviewDismissedEvent':
                    lines.append(f"### 🗑️ Review dismissed by @{actor_login} — {ts}")
                    lines.append("")
                    lines.append("---")
                    lines.append("")

                elif typename == 'CommentDeletedEvent':
                    lines.append(f"### 🗑️ Comment deleted by @{actor_login} — {ts}")
                    lines.append("")
                    lines.append("---")
                    lines.append("")

                elif typename == 'MarkedAsDuplicateEvent':
                    lines.append(f"### 📋 Marked as duplicate by @{actor_login} — {ts}")
                    lines.append("")
                    lines.append("---")
                    lines.append("")

                elif typename == 'UnmarkedAsDuplicateEvent':
                    lines.append(f"### 📋 Unmarked as duplicate by @{actor_login} — {ts}")
                    lines.append("")
                    lines.append("---")
                    lines.append("")

                elif typename == 'PinnedEvent':
                    lines.append(f"### 📌 Pinned by @{actor_login} — {ts}")
                    lines.append("")
                    lines.append("---")
                    lines.append("")

                elif typename == 'UnpinnedEvent':
                    lines.append(f"### 📌 Unpinned by @{actor_login} — {ts}")
                    lines.append("")
                    lines.append("---")
                    lines.append("")

                elif typename == 'SubscribedEvent':
                    lines.append(f"### 👀 Subscribed by @{actor_login} — {ts}")
                    lines.append("")
                    lines.append("---")
                    lines.append("")

                elif typename == 'UnsubscribedEvent':
                    lines.append(f"### 👀 Unsubscribed by @{actor_login} — {ts}")
                    lines.append("")
                    lines.append("---")
                    lines.append("")

                elif typename == 'TransferredEvent':
                    lines.append(f"### 📦 Transferred by @{actor_login} — {ts}")
                    lines.append("")
                    lines.append("---")
                    lines.append("")

                elif typename == 'ConnectedEvent':
                    lines.append(f"### 🔗 Connected by @{actor_login} — {ts}")
                    lines.append("")
                    lines.append("---")
                    lines.append("")

                elif typename == 'DisconnectedEvent':
                    lines.append(f"### 🔗 Disconnected by @{actor_login} — {ts}")
                    lines.append("")
                    lines.append("---")
                    lines.append("")

                elif typename == 'DeployedEvent':
                    lines.append(f"### 🚀 Deployed — {ts}")
                    lines.append("")
                    lines.append("---")
                    lines.append("")

                elif typename == 'DeploymentEnvironmentChangedEvent':
                    lines.append(f"### 🌍 Deployment environment changed — {ts}")
                    lines.append("")
                    lines.append("---")
                    lines.append("")

                elif typename == 'AddedToProjectEvent':
                    lines.append(f"### 📋 Added to project by @{actor_login} — {ts}")
                    lines.append("")
                    lines.append("---")
                    lines.append("")

                elif typename == 'RemovedFromProjectEvent':
                    lines.append(f"### 📋 Removed from project by @{actor_login} — {ts}")
                    lines.append("")
                    lines.append("---")
                    lines.append("")

                elif typename == 'MovedColumnsInProjectEvent':
                    lines.append(f"### 📋 Moved in project by @{actor_login} — {ts}")
                    lines.append("")
                    lines.append("---")
                    lines.append("")

                elif typename == 'ConvertedNoteToIssueEvent':
                    lines.append(f"### 📝 Converted note to issue by @{actor_login} — {ts}")
                    lines.append("")
                    lines.append("---")
                    lines.append("")

                elif typename == 'UserBlockedEvent':
                    lines.append(f"### 🚫 User blocked by @{actor_login} — {ts}")
                    lines.append("")
                    lines.append("---")
                    lines.append("")

                else:
                    # Fallback for unknown event types
                    if typename:
                        lines.append(f"### ℹ️ {typename} — {ts}")
                        if actor_login:
                            lines.append(f"by @{actor_login}")
                        lines.append("")
                        lines.append("---")
                        lines.append("")

        # --- Footer ---
        lines.append("")
        lines.append(f"---")
        lines.append(f"*Rendered from [{self.url}]({self.url})*")

        return '\n'.join(lines)

    # --- GitLab (REST) ---
    def _fetch_gitlab(self):
        headers = {"PRIVATE-TOKEN": self.token}
        project_enc = requests.utils.quote(f"{self.repo_owner}/{self.repo_name}", safe='')
        endpoint = "merge_requests" if self.is_pr else "issues"
        api_url = f"https://{self.domain}/api/v4/projects/{project_enc}/{endpoint}/{self.data_identifier}"
        resp = requests.get(api_url, headers=headers)
        if resp.status_code != 200: raise Exception(f"GitLab API Error: {resp.text}")
        data_raw = resp.json()

        # Activity Data (Notes + System Notes)
        activity_data = []
        notes_url = f"{api_url}/notes"
        notes_resp = requests.get(notes_url, headers=headers, params={"per_page": 100})
        notes_resp_json = notes_resp.json()

        issue = data_raw
        activity = notes_resp_json
        issue["notes"] = activity
        return issue, activity

    # --- Bitbucket (REST) ---
    def _fetch_bitbucket(self):
        assert(self.token)

        auth = None
        if ":" in self.token:
            user, pw = self.token.split(":", 1)
            auth = (user, pw)
        else:
            headers = {"Authorization": f"Bearer {self.token}"}
        
        endpoint = "pullrequests" if self.is_pr else "issues"
        api_url = f"https://api.bitbucket.org/2.0/repositories/{self.repo_owner}/{self.repo_name}/{endpoint}/{self.data_identifier}"
        
        req_kwargs = {'url': api_url}
        if auth: req_kwargs['auth'] = auth
        else: req_kwargs['headers'] = {"Authorization": f"Bearer {self.token}"}
        
        resp = requests.get(**req_kwargs)
        if resp.status_code != 200: raise Exception(f"Bitbucket API Error: {resp.text}")
        issue = resp.json() # Raw Issue/PR object

        # Fetch Comments (Bitbucket stores them separately)
        # Note: 'activity' endpoint is complex/paginated, using comments list here
        comments_url = issue['links']['comments']['href']
        c_resp = requests.get(comments_url, auth=auth) if auth else requests.get(comments_url, headers=headers)
        c_raw = c_resp.json()
        
        activity = c_raw.get('values', []) # Raw list of comments
        return issue, activity

    # --- Codeberg (Forgejo/Gitea REST) ---
    def _fetch_forgejo(self):
        headers = {"Authorization": f"token {self.token}"}
        
        endpoint = "pulls" if self.is_pr else "issues"
        api_url = f"https://{self.domain}/api/v1/repos/{self.repo_owner}/{self.repo_name}/{endpoint}/{self.data_identifier}"
        
        resp = requests.get(api_url, headers=headers)
        if resp.status_code != 200: raise Exception(f"Codeberg API Error: {resp.text}")
        issue = resp.json() # Raw Issue/PR object

        # Fetch Timeline (Comments + Events)
        timeline_url = f"{api_url}/timeline"
        t_resp = requests.get(timeline_url, headers=headers)
        activity = t_resp.json() # Raw list of timeline items
        
        return issue, activity

    # --- Sourcehut (GraphQL) ---
    def _fetch_srht(self):
        query = """
        query($username: String!, $trackerName: String!, $ticketId: Int!) {
          user(username: $username) {
            tracker(name: $trackerName) {
              ticket(id: $ticketId) {
                id
                subject
                status
                submitter { canonicalName }
                description
                labels { name }
                created
                updated
                comments {
                  results {
                    id
                    text
                    submitter { canonicalName }
                    created
                  }
                }
              }
            }
          }
        }
        """
        
        headers = {"Authorization": f"Bearer {self.token}"}
        vars = {'username': self.repo_owner, 'trackerName': self.repo_name, 'ticketId': self.data_identifier}
        
        resp = requests.post('https://git.sr.ht/query', json={'query': query, 'variables': vars}, headers=headers)
        if resp.status_code != 200: raise Exception(f"sr.ht API Error: {resp.text}")
        
        issue = resp.json()['data']['user']['tracker']['ticket']
        if not issue: raise Exception("Ticket not found")
        
        # Extract the raw comments list
        activity = issue.get('comments', {}).get('results', [])
        
        return issue, activity

    def _get_cache_path(self):
        """
        Generates the directory path for caching.
        Structure: git_data_cache/repoauthor/reponame/{issue or pr}/id
        """
        # Cannot be called uninitialized
        assert(self.domain is not None)
        assert(self.repo_name is not None)

        # Clean owner name (e.g. remove ~ from sr.ht users)
        clean_owner = self.repo_owner.replace('~', '')
        
        # Determine if it's an Issue or Pull Request
        type_str = 'pr' if self.is_pr else 'issue'
        
        # Construct path
        return os.path.join('git_data_cache', self.domain, clean_owner, self.repo_name, type_str, str(self.data_identifier))

    def _save_to_cache(self, path, issue_data, activity_data):
        """Saves raw dicts/lists to JSON in the cache directory."""
        os.makedirs(path, exist_ok=True)
        
        with open(os.path.join(path, "main.json"), 'w') as f:
            json.dump(issue_data, f, indent=2)
        
        with open(os.path.join(path, "activity.json"), 'w') as f:
            json.dump(activity_data, f, indent=2)
            
    def _load_from_cache(self, path):
        """Loads raw dicts/lists from JSON in the cache directory."""
        with open(os.path.join(path, "main.json"), 'r') as f:
            issue_data = json.load(f)
            
        with open(os.path.join(path, "activity.json"), 'r') as f:
            activity_data = json.load(f)
            
        return issue_data, activity_data

    def get_pr_commits(self):
        """Get all commits from a PR with their messages.
        
        Returns:
            list: List of dictionaries with keys: hash, message, url
        """
        if not self.is_pr:
            return []
        
        try:
            if self.engine == 'github':
                # GitHub REST API: GET /repos/{owner}/{repo}/pulls/{pull_number}/commits
                api_url = f"https://api.github.com/repos/{self.repo_owner}/{self.repo_name}/pulls/{self.data_identifier}/commits"
                headers = {"Authorization": f"Bearer {self.token}"}
                response = requests.get(api_url, headers=headers)
                if response.status_code == 200:
                    commits_data = response.json()
                    return [{
                        'hash': commit['sha'],
                        'message': commit['commit']['message'],
                        'url': commit['html_url']
                    } for commit in commits_data]
            
            elif self.engine == 'gitlab':
                # GitLab REST API: GET /projects/{id}/merge_requests/{iid}/commits
                project_enc = requests.utils.quote(f"{self.repo_owner}/{self.repo_name}", safe='')
                api_url = f"https://{self.domain}/api/v4/projects/{project_enc}/merge_requests/{self.data_identifier}/commits"
                headers = {"PRIVATE-TOKEN": self.token}
                response = requests.get(api_url, headers=headers)
                if response.status_code == 200:
                    commits_data = response.json()
                    return [{
                        'hash': commit['id'],
                        'message': commit['message'],
                        'url': commit['web_url']
                    } for commit in commits_data]
            
            # For other platforms or on error
            return []
            
        except Exception as e:
            print(f"Error getting commits from PR {self.url}: {e}")
            return []

    def extract_commit(self):
        """
        Get commit details for a specific commit hash in the current repo.
        
        Args:
            commit_hash (str): Commit hash
            
        Returns:
            dict: Commit details with keys: hash, message, url, author, date, etc.
                    Returns None if not found or error.
        """
        try:
            if self.engine == 'github':
                # GitHub REST API: GET /repos/{owner}/{repo}/commits/{sha}
                api_url = f"https://api.github.com/repos/{self.repo_owner}/{self.repo_name}/commits/{self.data_identifier}"
                headers = {"Authorization": f"token {self.token}"}
                response = requests.get(api_url, headers=headers)
                if response.status_code == 200:
                    commit_data = response.json()
                    return {
                        'hash': commit_data['sha'],
                        'message': commit_data['commit']['message'],
                        'url': commit_data['html_url'],
                        'author': commit_data['commit']['author']['name'] if commit_data['commit']['author'] else None,
                        'date': commit_data['commit']['author']['date'] if commit_data['commit']['author'] else None
                    }
                elif response.status_code in [404, 422]:
                    # print(f"Commit {self.data_identifier} not found in {self.repo_owner}/{self.repo_name}")
                    return None
            
            elif self.engine == 'gitlab':
                # GitLab REST API: GET /projects/{id}/repository/commits/{sha}
                project_enc = requests.utils.quote(f"{self.repo_owner}/{self.repo_name}", safe='')
                api_url = f"https://{self.domain}/api/v4/projects/{project_enc}/repository/commits/{self.data_identifier}"
                headers = {"PRIVATE-TOKEN": self.token}
                response = requests.get(api_url, headers=headers)
                if response.status_code == 200:
                    commit_data = response.json()
                    return {
                        'hash': commit_data['id'],
                        'message': commit_data['message'],
                        'url': commit_data['web_url'],
                        'author': commit_data['author_name'],
                        'date': commit_data['authored_date']
                    }
                elif response.status_code == 404:
                    # print(f"Commit {self.data_identifier} not found in {self.repo_owner}/{self.repo_name}")
                    return None
            else:
                # For other platforms (sourcehut, etc.) or unsupported
                print(f"Getting commit details not supported for {self.engine}")
            return None
            
        except Exception as e:
            print(f"Error getting commit {commit_hash} from {self.repo_owner}/{self.repo_name}: {e}")
            return None
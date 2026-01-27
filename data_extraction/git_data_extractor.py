import requests
import json
import re
import os
from urllib.parse import urlparse

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
        self.issue_number = None
        
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

        # print(f"Warning: No token found for domain '{self.domain}'. Proceeding without authentication.")
        return None

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
            self.issue_number = int(path_parts[3])
            self.is_pr = (type_str == 'pull')

        elif 'gitlab' in self.domain:
            self.engine = 'gitlab'
            # owner/repo/-/issues/123 OR owner/repo/-/merge_requests/123
            # Regex is safer for GitLab due to possible sub-groups
            match = re.search(r'gitlab\..*?/(.*?)/(.*?)/-/(issues|merge_requests)/(\d+)', self.url)
            if not match: raise ValueError("Invalid GitLab URL")
            self.repo_owner = match.group(1)
            self.repo_name = match.group(2)
            self.is_pr = (match.group(3) == 'merge_requests')
            self.issue_number = int(match.group(4))

        elif 'bitbucket.org' in self.domain:
            self.engine = 'bitbucket'
            # workspace/repo/issues/123
            if len(path_parts) < 4: raise ValueError("Invalid Bitbucket URL")
            self.repo_owner = path_parts[0]
            self.repo_name = path_parts[1]
            type_str = path_parts[2]
            self.issue_number = int(path_parts[3])
            self.is_pr = (type_str == 'pullrequests') # Bitbucket uses pullrequests

        elif 'codeberg.org' in self.domain:
            self.engine = 'forgejo' # Codeberg runs Forgejo
            # owner/repo/issues/123
            if len(path_parts) < 4: raise ValueError("Invalid Codeberg URL")
            self.repo_owner = path_parts[0]
            self.repo_name = path_parts[1]
            self.is_pr = (path_parts[2] == 'pulls') # Codeberg uses /pulls
            self.issue_number = int(path_parts[3])

        elif 'sr.ht' in self.domain:
            self.engine = 'sourcehut'
            # ~user/repo/123
            if len(path_parts) < 3: raise ValueError("Invalid sr.ht URL")
            self.repo_owner = path_parts[0].replace('~', '') # Strip tilde
            self.repo_name = path_parts[1]
            self.issue_number = int(path_parts[2])
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
            print(f"Loading from cache: {cache_path}")
            return self._load_from_cache(cache_path)
        
        # If not, fetch from API
        print(f"Fetching from API: {self.repo_owner}/{self.repo_name}...")
        
        df_issue = None
        df_activity = None
        
        if self.engine == 'github':
            df_issue, df_activity = self._fetch_github()
        elif self.engine == 'gitlab':
            df_issue, df_activity = self._fetch_gitlab()
        elif self.engine == 'bitbucket':
            df_issue, df_activity = self._fetch_bitbucket()
        elif self.engine == 'forgejo':
            df_issue, df_activity = self._fetch_forgejo()
        elif self.engine == 'sourcehut':
            df_issue, df_activity = self._fetch_srht()
        else:
            return None, None

        # Save to cache if successful
        if df_issue is not None:
            self._save_to_cache(cache_path, df_issue, df_activity)
            
        return df_issue, df_activity

    # --- GitHub (GraphQL) ---
    def _fetch_github(self):
        query = """
        query($owner: String!, $repo: String!, $number: Int!) {
          repository(owner: $owner, name: $repo) {
            issueOrPullRequest(number: $number) {
              ... on Issue {
                id: databaseId
                number
                title
                state
                author { login }
                body
                labels(first: 20) { nodes { name } }
                milestone { title }
                url
                timelineItems(first: 100) {
                  nodes {
                    ... on IssueComment {
                      id: databaseId
                      body
                    }
                    ... on ReferencedEvent {
                      commit { oid url }
                    }
                    ... on CrossReferencedEvent {
                      source {
                        ... on PullRequest { number url }
                      }
                    }
                  }
                }
              }
              ... on PullRequest {
                id: databaseId
                number
                title
                state
                author { login }
                body
                labels(first: 20) { nodes { name } }
                milestone { title }
                url
                mergedAt
                timelineItems(first: 100) {
                  nodes {
                    ... on IssueComment {
                      id: databaseId
                      body
                    }
                    ... on ReferencedEvent {
                      commit { oid url }
                    }
                  }
                }
              }
            }
          }
        }
        """
        
        headers = {"Authorization": f"Bearer {self.token}"}
        vars = {'owner': self.repo_owner, 'repo': self.repo_name, 'number': self.issue_number}
        
        resp = requests.post('https://api.github.com/graphql', json={'query': query, 'variables': vars}, headers=headers)
        if resp.status_code != 200: raise Exception(f"GitHub API Error: {resp.text}")
        resp_serialized = resp.json()
        data = resp_serialized['data']['repository']['issueOrPullRequest']
        activity_data = data.get('timelineItems', {}).get('nodes', [])

        issue = data
        activity = activity_data
        
        return issue, activity

    # --- GitLab (REST) ---
    def _fetch_gitlab(self):
        headers = {"PRIVATE-TOKEN": self.token}
        project_enc = requests.utils.quote(f"{self.repo_owner}/{self.repo_name}", safe='')
        endpoint = "merge_requests" if self.is_pr else "issues"
        api_url = f"https://{self.domain}/api/v4/projects/{project_enc}/{endpoint}/{self.issue_number}"
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
        api_url = f"https://api.bitbucket.org/2.0/repositories/{self.repo_owner}/{self.repo_name}/{endpoint}/{self.issue_number}"
        
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
        api_url = f"https://{self.domain}/api/v1/repos/{self.repo_owner}/{self.repo_name}/{endpoint}/{self.issue_number}"
        
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
        vars = {'username': self.repo_owner, 'trackerName': self.repo_name, 'ticketId': self.issue_number}
        
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
        return os.path.join('git_data_cache', self.domain, clean_owner, self.repo_name, type_str, str(self.issue_number))

    def _save_to_cache(self, path, issue_data, activity_data):
        """Saves raw dicts/lists to JSON in the cache directory."""
        os.makedirs(path, exist_ok=True)
        
        with open(os.path.join(path, "main.json"), 'w') as f:
            json.dump(issue_data, f, indent=2)
        
        with open(os.path.join(path, "activity.json"), 'w') as f:
            json.dump(activity_data, f, indent=2)
            
        print(f"Saved to cache: {path}")

    def _load_from_cache(self, path):
        """Loads raw dicts/lists from JSON in the cache directory."""
        with open(os.path.join(path, "main.json"), 'r') as f:
            issue_data = json.load(f)
            
        with open(os.path.join(path, "activity.json"), 'r') as f:
            activity_data = json.load(f)
            
        return issue_data, activity_data
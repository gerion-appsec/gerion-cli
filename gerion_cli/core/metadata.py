"""
Metadata handling for Gerion CLI.
"""
import os
import git
from pathlib import Path

def find_git_repo(path):
    """
    Find the Git repository root starting from the given path.
    Only checks the provided path itself and its immediate parent (1 level up max).
    This prevents searching indefinitely up the directory tree.
    Uses GitPython's search_parent_directories functionality in a controlled way.
    """
    path = Path(path).resolve()
    
    # Try to find repo starting from the provided path
    # GitPython will search up from this path, but we limit it by only checking
    # the path itself and its immediate parent
    try:
        # First try with search_parent_directories=True on the path itself
        # This will find the repo if path is inside a repo
        repo = git.Repo(str(path), search_parent_directories=True)
        repo_dir = repo.working_dir
        
        # Verify that the found repo is within reasonable distance (path or parent)
        repo_path = Path(repo_dir).resolve()
        if repo_path == path or repo_path == path.parent:
            return repo_dir
        # If repo is further up, don't use it (we only want 1 level up max)
    except (git.InvalidGitRepositoryError, git.NoSuchPathError):
        pass
    
    # If not found, try the parent directory directly
    parent = path.parent
    if parent != path:  # parent != path means not at root
        try:
            repo = git.Repo(str(parent), search_parent_directories=False)
            return repo.working_dir
        except (git.InvalidGitRepositoryError, git.NoSuchPathError):
            pass
    
    return None

def _detect_cicd_platform():
    """Detect the CI/CD platform from environment variables."""
    if os.getenv("JENKINS_URL"):
        return "jenkins"
    if os.getenv("GITHUB_ACTIONS"):
        return "github_actions"
    if os.getenv("GITLAB_CI"):
        return "gitlab_ci"
    if os.getenv("CIRCLECI"):
        return "circleci"
    if os.getenv("TF_BUILD"):  # Azure DevOps
        return "azure_devops"
    if os.getenv("BITBUCKET_BUILD_NUMBER"):
        return "bitbucket"
    return "local"


def _extract_repo_name_from_url(url: str) -> str:
    """Extract the repository short name from a remote URL."""
    if not url:
        return "local"
    clean = url[:-4] if url.endswith(".git") else url
    # Handle SSH (git@host:path/repo) and HTTPS (https://host/path/repo)
    if clean.startswith("git@"):
        parts = clean.split(":")
        path = parts[1] if len(parts) >= 2 else clean
    else:
        path = clean
    segments = [p for p in path.split("/") if p]
    return segments[-1] if segments else url


def get_metadata(code_path=None):
    """
    Get repository metadata from Git or environment variables.

    Args:
        code_path: Optional path to the code directory being scanned.
                   If provided, will search for Git repository starting from this path.
    """
    # Determine the base path for metadata collection
    if code_path:
        # Use the provided code_path, resolve to absolute path
        base_path = Path(code_path).resolve()
        # Find the Git repository root (might be a parent directory)
        git_repo_path = find_git_repo(base_path)
        if git_repo_path:
            repo_path = git_repo_path
        else:
            repo_path = str(base_path)
    else:
        # Fallback to current working directory
        repo_path = os.getcwd()

    metadata = {
        "repository_name": "local",
        "branch_name": "local",
        "build_id": "0",
        "code_path": str(code_path) if code_path else os.path.relpath(os.getcwd()),
        "commit_hash": None,
        "commit_author": None,
        "cicd_platform": _detect_cicd_platform(),
    }
    
    # Try to detect Git repository
    # Use search_parent_directories=False to prevent searching up indefinitely
    try:
        repo = git.Repo(repo_path, search_parent_directories=False)
        commit = repo.head.commit
        
        # Extract repository name from remote origin
        repo_name = "local"
        try:
            origin_url = repo.remotes.origin.url
            if origin_url:
                # Remove .git extension if present
                clean_url = origin_url
                if clean_url.endswith('.git'):
                    clean_url = clean_url[:-4]
                
                # Handle SSH URLs (git@domain:path)
                if clean_url.startswith('git@'):
                    parts = clean_url.split(':')
                    if len(parts) >= 2:
                        path_parts = [part for part in parts[1].split('/') if part]
                        if path_parts:
                            repo_name = path_parts[-1]
                else:
                    # Handle HTTPS URLs
                    parts = [part for part in clean_url.split('/') if part]
                    if parts:
                        repo_name = parts[-1]
        except:
            repo_name = os.path.basename(repo.working_dir)
        
        # Use the code_path if provided, otherwise use repo working dir
        final_code_path = str(code_path) if code_path else repo.working_dir
        
        metadata.update({
            "repository_name": repo_name,
            "branch_name": repo.active_branch.name,
            "build_id": "0",
            "code_path": final_code_path,
            "commit_hash": commit.hexsha,
            "commit_author": commit.author.name
        })
    except Exception:
        pass

    # Override with CI/CD environment variables
    if os.getenv("GITHUB_SERVER_URL"):
        metadata.update({
            "repository_name": os.getenv("GITHUB_REPOSITORY"),
            "branch_name": os.getenv("GITHUB_HEAD_REF") or os.getenv("GITHUB_REF_NAME"),
            "build_id": os.getenv("GITHUB_RUN_ATTEMPT"),
            "code_path": os.getenv("GITHUB_WORKSPACE"),
            "commit_hash": os.getenv("GITHUB_WORKFLOW_SHA"),
            "commit_author": os.getenv("GITHUB_ACTOR")
        })

    if os.getenv("JENKINS_URL"):
        # Jenkins sets GIT_BRANCH with "origin/" prefix (e.g. "origin/main") — strip it.
        raw_branch = os.getenv("GIT_BRANCH", "")
        branch_name = raw_branch[len("origin/"):] if raw_branch.startswith("origin/") else raw_branch

        # Jenkins sets GIT_URL to the full remote URL — extract the short repo name.
        repo_name = _extract_repo_name_from_url(os.getenv("GIT_URL", "")) or "local"

        metadata.update({
            "repository_name": repo_name,
            "branch_name": branch_name,
            "build_id": os.getenv("BUILD_NUMBER"),
            "code_path": os.getenv("WORKSPACE"),
            "commit_hash": os.getenv("GIT_COMMIT"),
            "commit_author": os.getenv("GIT_COMMITTER_NAME"),
        })
    
    if os.getenv("GITLAB_CI"):
        metadata.update({
            "repository_name": os.getenv("CI_PROJECT_NAME"),
            "branch_name": os.getenv("CI_MERGE_REQUEST_SOURCE_BRANCH_NAME") or os.getenv("CI_COMMIT_REF_NAME"),
            "build_id": os.getenv("CI_CONCURRENT_ID"),
            "code_path": os.getenv("CI_BUILDS_DIR"),
            "commit_hash": os.getenv("CI_COMMIT_SHA"),
            "commit_author": os.getenv("CI_COMMIT_AUTHOR")
        })
    
    # Override with manual environment variables
    manual_updates = {}
    if os.getenv("GERION_REPO_NAME"):
        manual_updates["repository_name"] = os.getenv("GERION_REPO_NAME")
    if os.getenv("GERION_BRANCH_NAME"):
        manual_updates["branch_name"] = os.getenv("GERION_BRANCH_NAME")
    if os.getenv("GERION_COMMIT_HASH"):
        manual_updates["commit_hash"] = os.getenv("GERION_COMMIT_HASH")
    if os.getenv("GERION_BUILD_ID"):
        manual_updates["build_id"] = os.getenv("GERION_BUILD_ID")
    
    if manual_updates:
        metadata.update(manual_updates)
    
    return metadata 
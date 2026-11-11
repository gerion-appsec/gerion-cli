"""
Metadata handling for Gerion CLI.
"""
import os
import subprocess
from pathlib import Path

from gerion_cli.core.logging import debug

GIT_TIMEOUT = 10
# Never prompt for credentials and never take optional locks (no index refresh) in
# the scanned repository. GIT_DIR/GIT_WORK_TREE (set e.g. inside git hooks) would
# make git ignore the -C directory.
_GIT_ENV_DROP = ("GIT_DIR", "GIT_WORK_TREE")


def _git(cwd, *args: str) -> str | None:
    """
    Run a read-only git command in `cwd` and return its stripped stdout, or None if
    git is not installed, fails, or times out.
    """
    env = {k: v for k, v in os.environ.items() if k not in _GIT_ENV_DROP}
    env.update(GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0")
    try:
        process = subprocess.run(
            ["git", "-C", str(cwd), *args],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            errors="replace",
            env=env,
            timeout=GIT_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        debug(f"git {args[0]} failed: {e}")
        return None
    if process.returncode != 0:
        return None
    return process.stdout.strip()


def _git_toplevel(path: Path) -> str | None:
    """Top-level directory of the work tree containing `path`, or None."""
    return _git(path, "rev-parse", "--show-toplevel") or None


def find_git_repo(path):
    """
    Find the Git repository root starting from the given path.
    Only the provided path itself and its immediate parent (1 level up max) are
    accepted as the root, so an unrelated repository further up the tree (e.g. the
    user's home directory) is never used.
    """
    path = Path(path).resolve()
    toplevel = _git_toplevel(path if path.is_dir() else path.parent)
    if toplevel:
        repo_path = Path(toplevel).resolve()
        if repo_path == path or repo_path == path.parent:
            return toplevel
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
    # Determine the repository root: metadata is only read from a repository whose
    # root is the scanned path or its parent (or the current directory itself).
    if code_path:
        repo_root = find_git_repo(Path(code_path).resolve())
    else:
        cwd = os.getcwd()
        toplevel = _git_toplevel(Path(cwd))
        repo_root = toplevel if toplevel and Path(toplevel).resolve() == Path(cwd).resolve() else None

    metadata = {
        "repository_name": "local",
        "branch_name": "local",
        "build_id": "0",
        "code_path": str(code_path) if code_path else os.path.relpath(os.getcwd()),
        "commit_hash": None,
        "commit_author": None,
        "cicd_platform": _detect_cicd_platform(),
    }

    # Fails in a repository without commits: keep the defaults.
    head = _git(repo_root, "log", "-1", "--no-show-signature", "--format=%H%n%an", "HEAD") if repo_root else None
    if head:
        commit_hash, _, commit_author = head.partition("\n")
        # No origin remote: fall back to the directory name.
        origin_url = _git(repo_root, "config", "--get", "remote.origin.url")
        repo_name = _extract_repo_name_from_url(origin_url) if origin_url else os.path.basename(repo_root)

        metadata.update({
            "repository_name": repo_name,
            "build_id": "0",
            # Use the code_path if provided, otherwise use the repository root
            "code_path": str(code_path) if code_path else repo_root,
            "commit_hash": commit_hash,
            "commit_author": commit_author,
        })
        # A detached HEAD (git checkout <sha>, the norm on most CI systems) has no
        # branch: keep the default instead of losing the rest of the metadata.
        branch = _git(repo_root, "symbolic-ref", "--short", "-q", "HEAD")
        if branch:
            metadata["branch_name"] = branch
    else:
        debug("Git metadata unavailable: not a repository, a repository without commits, or git is not installed.")

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

import os
import pytest
from unittest.mock import patch, MagicMock
from gerion_cli.core.metadata import get_metadata

@patch("gerion_cli.core.metadata.git.Repo")
@patch.dict(os.environ, {}, clear=True)
def test_get_metadata_git(mock_repo_cls):
    """Test metadata extraction from mocked Git repository."""
    # Setup mock repo
    mock_repo = MagicMock()
    mock_repo.working_dir = "/mock/repo"
    mock_repo.active_branch.name = "feature-branch"
    mock_repo.head.commit.hexsha = "deadbeef123456"
    mock_repo.head.commit.author.name = "Git User"
    mock_repo.remotes.origin.url = "git@github.com:myorg/myrepo.git"
    
    mock_repo_cls.side_effect = lambda p, search_parent_directories=False: mock_repo
    
    with patch("os.getcwd", return_value="/mock/repo"):
        metadata = get_metadata()
    
    assert metadata["repository_name"] == "myrepo"
    assert metadata["branch_name"] == "feature-branch"
    assert metadata["commit_hash"] == "deadbeef123456"
    assert metadata["commit_author"] == "Git User"
    assert metadata["code_path"] == "/mock/repo"

@patch.dict(os.environ, {
    "GITHUB_SERVER_URL": "https://github.com",
    "GITHUB_REPOSITORY": "ci-org/ci-repo",
    "GITHUB_HEAD_REF": "ci-branch",
    "GITHUB_RUN_ATTEMPT": "42",
    "GITHUB_WORKSPACE": "/ci/workspace",
    "GITHUB_WORKFLOW_SHA": "cifacade",
    "GITHUB_ACTOR": "CI Bot"
}, clear=True)
def test_get_metadata_github_actions():
    """Test metadata extraction from GitHub Actions environment."""
    metadata = get_metadata()
    
    assert metadata["repository_name"] == "ci-org/ci-repo"
    assert metadata["branch_name"] == "ci-branch"
    assert metadata["build_id"] == "42"
    assert metadata["commit_hash"] == "cifacade"
    assert metadata["commit_author"] == "CI Bot"

@patch.dict(os.environ, {
    "GERION_REPO_NAME": "manual-repo",
    "GERION_BRANCH_NAME": "manual-branch"
}, clear=True)
def test_get_metadata_manual_override():
    """Test manual environment variable overrides."""
    metadata = get_metadata()
    
    assert metadata["repository_name"] == "manual-repo"
    assert metadata["branch_name"] == "manual-branch"

import os
import subprocess
from unittest.mock import patch

import pytest

from gerion_cli.core import metadata as metadata_module
from gerion_cli.core.metadata import find_git_repo, get_metadata

# Deterministic identity and no user/system config for the test repositories.
_GIT_ENV = {
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_AUTHOR_NAME": "Git User",
    "GIT_AUTHOR_EMAIL": "git@example.com",
    "GIT_COMMITTER_NAME": "Committer",
    "GIT_COMMITTER_EMAIL": "committer@example.com",
}


def _git(repo, *args):
    env = {**os.environ, **_GIT_ENV}
    return subprocess.run(
        ["git", "-C", str(repo), *args], env=env, capture_output=True, text=True, check=True
    ).stdout.strip()


def _make_repo(path, commit=True, origin=None, branch="feature-branch"):
    path.mkdir(parents=True, exist_ok=True)
    _git(path, "init", "-q", "-b", branch)
    if commit:
        (path / "f.txt").write_text("x")
        _git(path, "add", "f.txt")
        _git(path, "commit", "-q", "-m", "init")
    if origin:
        _git(path, "remote", "add", "origin", origin)
    return path


@pytest.fixture(autouse=True)
def _isolated_git_config(monkeypatch):
    # get_metadata runs git with the inherited environment: keep the user's
    # config (e.g. log.showSignature) out of the tests.
    for key, value in _GIT_ENV.items():
        if key.startswith("GIT_CONFIG"):
            monkeypatch.setenv(key, value)


def test_get_metadata_git(tmp_path, monkeypatch):
    """Metadata extraction from a real Git repository (cwd is the repository root)."""
    repo = _make_repo(tmp_path / "work", origin="git@github.com:myorg/myrepo.git")
    sha = _git(repo, "rev-parse", "HEAD")
    for var in ("GITHUB_SERVER_URL", "JENKINS_URL", "GITLAB_CI", "GERION_REPO_NAME", "GERION_BRANCH_NAME",
                "GERION_COMMIT_HASH", "GERION_BUILD_ID"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.chdir(repo)

    metadata = get_metadata()

    assert metadata["repository_name"] == "myrepo"
    assert metadata["branch_name"] == "feature-branch"
    assert metadata["commit_hash"] == sha
    assert metadata["commit_author"] == "Git User"
    assert metadata["code_path"] == str(repo.resolve())


@patch.dict(os.environ, {}, clear=True)
def test_get_metadata_subdirectory_uses_parent_repo(tmp_path):
    repo = _make_repo(tmp_path / "proj", origin="https://github.com/org/proj.git")
    (repo / "src").mkdir()
    metadata = get_metadata(code_path=str(repo / "src"))
    assert metadata["repository_name"] == "proj"
    assert metadata["code_path"] == str(repo / "src")


@patch.dict(os.environ, {}, clear=True)
def test_find_git_repo_ignores_repos_more_than_one_level_up(tmp_path):
    repo = _make_repo(tmp_path / "proj")
    deep = repo / "a" / "b"
    deep.mkdir(parents=True)
    assert find_git_repo(deep) is None
    assert find_git_repo(repo / "a") == str(repo.resolve())
    assert get_metadata(code_path=str(deep))["commit_hash"] is None


@patch.dict(os.environ, {}, clear=True)
def test_get_metadata_without_origin_uses_directory_name(tmp_path):
    repo = _make_repo(tmp_path / "my-project")
    metadata = get_metadata(code_path=str(repo))
    assert metadata["repository_name"] == "my-project"
    assert metadata["branch_name"] == "feature-branch"


@patch.dict(os.environ, {}, clear=True)
def test_get_metadata_not_a_repository(tmp_path):
    metadata = get_metadata(code_path=str(tmp_path))
    assert metadata["repository_name"] == "local"
    assert metadata["branch_name"] == "local"
    assert metadata["build_id"] == "0"
    assert metadata["commit_hash"] is None
    assert metadata["commit_author"] is None


def test_get_metadata_without_git_installed(tmp_path, monkeypatch):
    repo = _make_repo(tmp_path / "proj")
    for var in ("GITHUB_SERVER_URL", "JENKINS_URL", "GITLAB_CI", "GERION_REPO_NAME", "GERION_COMMIT_HASH"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("PATH", str(tmp_path / "no-bin"))
    metadata = get_metadata(code_path=str(repo))
    assert metadata["repository_name"] == "local"
    assert metadata["commit_hash"] is None


def test_git_runs_without_prompts_or_optional_locks(monkeypatch):
    seen = {}

    def fake_run(argv, **kwargs):
        seen.update(argv=argv, **kwargs)
        return subprocess.CompletedProcess(argv, 0, stdout="out\n")

    monkeypatch.setenv("GIT_DIR", "/elsewhere/.git")
    monkeypatch.setattr(metadata_module.subprocess, "run", fake_run)
    assert metadata_module._git("/repo", "config", "--get", "remote.origin.url") == "out"
    assert seen["argv"] == ["git", "-C", "/repo", "config", "--get", "remote.origin.url"]
    assert seen["env"]["GIT_TERMINAL_PROMPT"] == "0"
    assert seen["env"]["GIT_OPTIONAL_LOCKS"] == "0"
    assert "GIT_DIR" not in seen["env"]
    assert seen["stdin"] is subprocess.DEVNULL
    assert seen["timeout"]


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


@patch.dict(os.environ, {}, clear=True)
def test_get_metadata_detached_head_keeps_repo_and_commit(tmp_path):
    """CI checkouts (git checkout <sha>) have no branch; the rest must not be lost."""
    repo = _make_repo(tmp_path / "work", origin="git@github.com:myorg/myrepo.git")
    sha = _git(repo, "rev-parse", "HEAD")
    _git(repo, "checkout", "-q", "--detach", sha)

    metadata = get_metadata(code_path=str(repo))

    assert metadata["repository_name"] == "myrepo"
    assert metadata["commit_hash"] == sha
    assert metadata["commit_author"] == "Git User"
    assert metadata["branch_name"] == "local"


@patch.dict(os.environ, {}, clear=True)
def test_get_metadata_repo_without_commits(tmp_path):
    _make_repo(tmp_path / "work", commit=False)
    metadata = get_metadata(code_path=str(tmp_path / "work"))
    assert metadata["repository_name"] == "local"
    assert metadata["commit_hash"] is None


_GITHUB = {"GITHUB_SERVER_URL": "https://github.com", "GITHUB_REPOSITORY": "o/r"}
_GITLAB = {"GITLAB_CI": "true", "CI_PROJECT_NAME": "proj"}


@pytest.mark.parametrize("env, expected", [
    ({**_GITHUB, "GITHUB_RUN_ID": "9001", "GITHUB_RUN_ATTEMPT": "2"}, "9001"),
    ({**_GITHUB, "GITHUB_RUN_ATTEMPT": "2"}, "2"),
    ({**_GITHUB, "GITHUB_RUN_ID": "abc", "GITHUB_RUN_ATTEMPT": "3"}, "3"),
    ({**_GITHUB}, "0"),
    ({**_GITLAB, "CI_PIPELINE_ID": "77", "CI_JOB_ID": "5", "CI_CONCURRENT_ID": "1"}, "77"),
    ({**_GITLAB, "CI_JOB_ID": "5", "CI_CONCURRENT_ID": "1"}, "5"),
    ({**_GITLAB, "CI_CONCURRENT_ID": "1"}, "1"),
    ({**_GITLAB, "CI_PIPELINE_ID": "", "CI_JOB_ID": "x1"}, "0"),
    ({"JENKINS_URL": "http://j", "BUILD_NUMBER": "12"}, "12"),
    ({"JENKINS_URL": "http://j"}, "0"),
    ({"JENKINS_URL": "http://j", "BUILD_NUMBER": "#12"}, "0"),
])
def test_ci_build_id_is_numeric_with_fallbacks(env, expected, tmp_path):
    with patch.dict(os.environ, env, clear=True):
        assert get_metadata(code_path=str(tmp_path))["build_id"] == expected


def test_gerion_build_id_override_wins_and_warns_when_not_numeric(tmp_path):
    env = {**_GITHUB, "GITHUB_RUN_ID": "9001", "GERION_BUILD_ID": "123-2"}
    with patch.dict(os.environ, env, clear=True), patch.object(metadata_module, "warning") as warn:
        assert get_metadata(code_path=str(tmp_path))["build_id"] == "123-2"
    warn.assert_called_once()
    assert "numeric" in warn.call_args.args[0]


def test_gerion_build_id_numeric_does_not_warn(tmp_path):
    with patch.dict(os.environ, {"GERION_BUILD_ID": "55"}, clear=True), patch.object(metadata_module, "warning") as warn:
        assert get_metadata(code_path=str(tmp_path))["build_id"] == "55"
    warn.assert_not_called()

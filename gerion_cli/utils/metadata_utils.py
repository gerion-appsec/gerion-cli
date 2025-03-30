import os
import git

def get_metadata():
    try:
        repo = git.Repo()
    
        commit = repo.head.commit
        metadata = {
            "repository_name":  os.path.basename(repo.working_dir),
            "branch_name": repo.active_branch.name,
            "build_id": "0",
            "code_path": repo.working_dir,
            "commit_hash": commit.hexsha,
            "commit_author": commit.author.name
        }
    except Exception:
        metadata = {
            "repository_name": os.path.relpath(os.getcwd()),
            "branch_name": "local",
            "build_id": "0",
            "code_path": os.path.relpath(os.getcwd()),
            "commit_hash": None,
            "commit_author": None
        }

    if os.getenv("GITHUB_SERVER_URL"):
        metadata["repository_name"] = os.getenv("GITHUB_REPOSITORY")
        metadata["branch_name"] = os.getenv("GITHUB_HEAD_REF") or os.getenv("GITHUB_REF_NAME")
        metadata["build_id"] = os.getenv("GITHUB_RUN_ATTEMPT")
        metadata["code_path"] = os.getenv("GITHUB_WORKSPACE")
        metadata["commit_hash"] = os.getenv("GITHUB_WORKFLOW_SHA")
        metadata["commit_author"] = os.getenv("GITHUB_ACTOR")

    if os.getenv("JENKINS_URL"):
        metadata["repository_name"] = os.getenv("GIT_URL")
        metadata["branch_name"] = os.getenv("GIT_BRANCH")
        metadata["build_id"] = os.getenv("BUILD_NUMBER")
        metadata["code_path"] = os.getenv("WORKSPACE")
        metadata["commit_hash"] = os.getenv("GIT_COMMIT")
        metadata["commit_author"] = os.getenv("GIT_COMMITTER_NAME")
    
    if os.getenv("GITLAB_CI"):
        metadata["repository_name"] = os.getenv("CI_PROJECT_NAME")
        metadata["branch_name"] = os.getenv("CI_MERGE_REQUEST_SOURCE_BRANCH_NAME") or os.getenv("CI_COMMIT_REF_NAME")
        metadata["build_id"] = os.getenv("CI_CONCURRENT_ID")
        metadata["code_path"] = os.getenv("CI_BUILDS_DIR")
        metadata["commit_hash"] = os.getenv("CI_COMMIT_SHA")
        metadata["commit_author"] = os.getenv("CI_COMMIT_AUTHOR")
    
    return metadata
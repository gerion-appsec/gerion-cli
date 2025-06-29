"""
Metadata handling for Gerion CLI.
"""
import os
import git

def get_metadata():
    """Get repository metadata from Git or environment variables."""
    metadata = {
        "repository_name": "local",
        "branch_name": "local",
        "build_id": "0",
        "code_path": os.path.relpath(os.getcwd()),
        "commit_hash": None,
        "commit_author": None
    }
    
    # Try to detect Git repository
    try:
        repo = git.Repo()
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
        
        metadata.update({
            "repository_name": repo_name,
            "branch_name": repo.active_branch.name,
            "build_id": "0",
            "code_path": repo.working_dir,
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
        metadata.update({
            "repository_name": os.getenv("GIT_URL"),
            "branch_name": os.getenv("GIT_BRANCH"),
            "build_id": os.getenv("BUILD_NUMBER"),
            "code_path": os.getenv("WORKSPACE"),
            "commit_hash": os.getenv("GIT_COMMIT"),
            "commit_author": os.getenv("GIT_COMMITTER_NAME")
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
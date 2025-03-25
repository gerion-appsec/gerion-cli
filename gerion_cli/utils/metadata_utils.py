import os

def get_metadata():
    return {
        "repository_name": os.getenv("REPOSITORY_NAME"),
        "branch_name": os.getenv("BRANCH_NAME"),
        "build_id": os.getenv("BUILD_ID"),
        "code_path": os.getenv("CODE_PATH"),
    }
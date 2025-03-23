import os

def get_metadata():
    return {
        "REPOSITORY_NAME": os.getenv("REPOSITORY_NAME"),
        "BRANCH_NAME": os.getenv("BRANCH_NAME"),
        "BUILD_ID": os.getenv("BUILD_ID"),
        "CODE_PATH": os.getenv("CODE_PATH"),
    }
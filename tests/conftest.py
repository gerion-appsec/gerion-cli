import pytest
import json
import os
from pathlib import Path

@pytest.fixture
def fixtures_dir():
    """Return the path to the fixtures directory."""
    return Path(__file__).parent / "fixtures"

@pytest.fixture
def load_fixture(fixtures_dir):
    """Load a JSON fixture file."""
    def _load(filename):
        with open(fixtures_dir / filename, "r") as f:
            return json.load(f)
    return _load

@pytest.fixture
def mock_metadata():
    """Return a standard metadata dictionary for testing."""
    return {
        "repository_name": "test-repo",
        "branch_name": "test-branch",
        "build_id": "123",
        "code_path": "/tmp/test-code",
        "commit_hash": "abcdef123456",
        "commit_author": "Test Author"
    }

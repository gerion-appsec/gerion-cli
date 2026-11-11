import json
import os
from pathlib import Path

import pytest

# Render CLI output without ANSI styling, whatever the host environment. CI runners
# (GITHUB_ACTIONS, FORCE_COLOR) make Rich style the help text, which splits option
# names like "--fail-on" across escape sequences and breaks plain substring
# assertions. This runs at import time because the Rich consoles are created when
# gerion_cli is first imported, before any fixture.
for _name in ("GITHUB_ACTIONS", "FORCE_COLOR", "PY_COLORS", "CLICOLOR_FORCE"):
    os.environ.pop(_name, None)
os.environ["NO_COLOR"] = "1"
os.environ["TERM"] = "dumb"


@pytest.fixture
def fixtures_dir():
    """Return the path to the fixtures directory."""
    return Path(__file__).parent / "fixtures"

@pytest.fixture
def load_fixture(fixtures_dir):
    """Load a JSON fixture file."""
    def _load(filename):
        with open(fixtures_dir / filename) as f:
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

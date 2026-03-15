import pytest
import os
import json
from gerion_cli.output.formats import save_to_file
from gerion_cli.core.types import OutputFormat

@pytest.fixture
def sample_results(mock_metadata):
    return {
        "metadata": mock_metadata,
        "findings": [
            {
                "finding_id": "123",
                "title": "Test Finding",
                "description": "A test finding description.",
                "severity": "High",
                "file_path": "test.py",
                "line_number": 10
            }
        ]
    }

def test_save_json(sample_results, tmp_path):
    """Test saving results as JSON."""
    output_file = tmp_path / "results.json"
    save_to_file(sample_results, str(output_file), OutputFormat.JSON)
    
    assert output_file.exists()
    with open(output_file) as f:
        data = json.load(f)
        assert data["findings"][0]["title"] == "Test Finding"

def test_save_markdown(sample_results, tmp_path):
    """Test saving results as Markdown."""
    output_file = tmp_path / "results.md"
    save_to_file(sample_results, str(output_file), OutputFormat.MARKDOWN)
    
    assert output_file.exists()
    content = output_file.read_text()
    assert "# Security Scan Report" in content
    assert "Test Finding" in content
    assert "test.py" in content

def test_save_sarif(sample_results, tmp_path):
    """Test saving results as SARIF."""
    output_file = tmp_path / "results.sarif"
    save_to_file(sample_results, str(output_file), OutputFormat.SARIF)
    
    assert output_file.exists()
    with open(output_file) as f:
        data = json.load(f)
        assert len(data["runs"]) == 1
        assert data["runs"][0]["tool"]["driver"]["name"] == "Gerion Security Scanner"
        assert len(data["runs"][0]["results"]) == 1
        assert data["runs"][0]["results"][0]["ruleId"] == "123"

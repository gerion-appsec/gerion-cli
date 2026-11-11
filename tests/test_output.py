import json

import pytest

from gerion_cli.core.types import OutputFormat
from gerion_cli.output.formats import save_to_file


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


def _sarif_finding(**overrides):
    finding = {
        "finding_id": "abc123", "title": "t", "description": "d", "severity": "HIGH",
        "scan_type": "SCA", "file_path": "requirements.txt", "line_number": None,
        "cve": ["CVE-2024-1", "CVE-2024-2"], "component_name": "django", "component_version": "4.2.1",
    }
    finding.update(overrides)
    return finding


@pytest.mark.parametrize(("severity", "level"), [
    ("CRITICAL", "error"), ("HIGH", "error"), ("High", "error"), ("MEDIUM", "warning"),
    ("Medium", "warning"), ("LOW", "note"), ("INFO", "note"), (None, "note"),
])
def test_sarif_level_is_case_insensitive(severity, level):
    from gerion_cli.output.formats import generate_sarif_content
    sarif = generate_sarif_content({"metadata": {}, "findings": [_sarif_finding(severity=severity)]})
    assert sarif["runs"][0]["results"][0]["level"] == level


@pytest.mark.parametrize(("line_number", "expected"), [(None, 1), (0, 1), (12, 12), ("7", 7), ("x", 1)])
def test_sarif_start_line_is_positive_int(line_number, expected):
    from gerion_cli.output.formats import generate_sarif_content
    sarif = generate_sarif_content({"metadata": {}, "findings": [_sarif_finding(line_number=line_number)]})
    region = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] == expected


def test_sarif_run_metadata_and_fingerprints():
    from datetime import UTC, datetime, timedelta

    from gerion_cli.core.config import __version__
    from gerion_cli.output.formats import generate_sarif_content

    sarif = generate_sarif_content({
        "metadata": {"scan_type": "All"},
        "findings": [_sarif_finding(cve="CVE-2024-9", file_path="dir with space/a.py")],
    })
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["version"] == __version__
    assert run["tool"]["driver"]["name"] == "Gerion All Scanner"

    started = datetime.strptime(run["invocations"][0]["startTimeUtc"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    assert abs(datetime.now(UTC) - started) < timedelta(minutes=1)

    result = run["results"][0]
    assert result["ruleId"] == "abc123"
    assert result["partialFingerprints"] == {"gerionFindingId/v1": "abc123"}
    assert result["properties"]["cve"] == ["CVE-2024-9"]
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "dir%20with%20space/a.py"
    json.dumps(sarif)  # serialisable


def test_markdown_escapes_table_cells_and_joins_cves():
    from gerion_cli.output.formats import generate_markdown_content

    findings = [_sarif_finding(file_path="a|b.txt"), _sarif_finding(scan_type="Secrets", title="x | y\nz")]
    sca = generate_markdown_content({"metadata": {}, "findings": findings[:1]})
    assert "CVE-2024-1, CVE-2024-2" in sca
    assert "['CVE" not in sca
    assert "`a\\|b.txt`" in sca

    secrets = generate_markdown_content({"metadata": {}, "findings": findings[1:]})
    row = next(line for line in secrets.splitlines() if "x \\| y z" in line)
    assert row.count(" | ") == 2  # Severity | Title | File:Line

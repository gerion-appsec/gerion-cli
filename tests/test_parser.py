import pytest
import json
from gerion_cli.tools.parser import (
    parse_secrets_tool_output,
    parse_sca_tool_output,
    parse_sast_tool_output,
    parse_iac_tool_output
)

def test_parse_secrets_gitleaks(load_fixture, mock_metadata):
    """Test parsing Gitleaks output."""
    data = load_fixture("gitleaks.json")
    findings = parse_secrets_tool_output(data, mock_metadata)
    
    assert len(findings) > 0
    f = findings[0]
    
    assert f["scan_type"] == "Secrets"
    assert f["severity"] == "High"
    assert "Hard coded secret" in f["title"]
    assert f["file_path"] == "appsettings.json"
    assert f["finding_id"] is not None
    # Ensure secret is redacted in mitigation
    assert "[REDACTED]" in f["mitigation"]

def test_parse_sca_osv(load_fixture, mock_metadata):
    """Test parsing OSV-Scanner output."""
    data = load_fixture("osv.json")
    # OSV-Scanner output is wrapped in "results" list, but we need to pass the list itself
    # if it's not the root element.
    findings = parse_sca_tool_output(data.get("results", []), mock_metadata)
    
    assert len(findings) > 0
    f = findings[0]
    
    assert f["scan_type"] == "SCA"
    assert f["component_name"] is not None
    assert f["cve"] is not None
    assert f["severity"] in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    assert f["file_path"] != "unknown"

def test_parse_sast_opengrep(load_fixture, mock_metadata):
    """Test parsing Opengrep output."""
    data = load_fixture("opengrep.json")
    findings = parse_sast_tool_output(data.get("results", []), mock_metadata)
    
    assert len(findings) > 0
    f = findings[0]
    
    assert f["scan_type"] == "SAST"
    assert f["rule_id"] is not None if "rule_id" in f else f["title"] is not None
    assert f["severity"] in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    assert f["file_path"].endswith("docker-compose.yml")

def test_parse_iac_kics(load_fixture, mock_metadata):
    """Test parsing KICS output."""
    data = load_fixture("kics.json")
    findings = parse_iac_tool_output(data.get("queries", []), mock_metadata)
    
    assert len(findings) > 0
    f = findings[0]
    
    assert f["scan_type"] == "IaC"
    assert f["title"] == "Passwords And Secrets - Generic Password"
    assert f["severity"] == "HIGH"
    assert "Dockerfile" in f["file_path"]

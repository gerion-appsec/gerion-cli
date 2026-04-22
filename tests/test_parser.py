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
    """Test parsing OSV-Scanner output with package-level grouping."""
    data = load_fixture("osv.json")
    findings = parse_sca_tool_output(data.get("results", []), mock_metadata)

    # certifi (2 CVEs) + django (1 CVE) = 2 findings, one per package
    assert len(findings) == 2

    certifi_finding = next((f for f in findings if f["component_name"] == "certifi"), None)
    assert certifi_finding is not None, "certifi finding not found"

    assert isinstance(certifi_finding["cve"], list), "cve must be a list"
    assert len(certifi_finding["cve"]) == 2
    assert "CVE-2022-23491" in certifi_finding["cve"]
    assert "CVE-2023-37920" in certifi_finding["cve"]

    # HIGH beats MEDIUM
    assert certifi_finding["severity"] == "HIGH"

    # 2023.07.22 > 2022.12.07
    assert certifi_finding["component_fix"] == "2023.07.22"

    assert isinstance(certifi_finding["cwe"], list)
    assert "CWE-345" in certifi_finding["cwe"]

    assert certifi_finding["finding_id"] is not None
    assert len(certifi_finding["finding_id"]) == 12

    assert certifi_finding["scan_type"] == "SCA"
    assert certifi_finding["file_path"] != "unknown"
    assert certifi_finding["component_name"] == "certifi"
    assert certifi_finding["component_version"] == "2019.11.28"

    django_finding = next((f for f in findings if f["component_name"] == "django"), None)
    assert django_finding is not None, "django finding not found"
    assert isinstance(django_finding["cve"], list)
    assert len(django_finding["cve"]) == 1
    assert django_finding["cve"][0] == "CVE-2020-13596"
    assert django_finding["severity"] == "MEDIUM"

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

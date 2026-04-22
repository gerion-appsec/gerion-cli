import pytest
import json
from gerion_cli.tools.parser import (
    parse_secrets_tool_output,
    parse_sca_tool_output,
    parse_sast_tool_output,
    parse_iac_tool_output,
    _parse_ghsa_sections,
    _build_description_from_sections,
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

    # vuln_details: sorted by severity desc, include cvss field
    vd = certifi_finding["vuln_details"]
    assert len(vd) == 2
    assert vd[0]["severity"] == "HIGH"   # most severe first
    assert vd[1]["severity"] == "MEDIUM"
    assert vd[0]["cvss"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    assert vd[1]["cvss"] is None         # no severity list in fixture for MODERATE entry

    django_finding = next((f for f in findings if f["component_name"] == "django"), None)
    assert django_finding is not None, "django finding not found"
    assert isinstance(django_finding["cve"], list)
    assert len(django_finding["cve"]) == 1
    assert django_finding["cve"][0] == "CVE-2020-13596"
    assert django_finding["severity"] == "MEDIUM"

    # description must come from ### Impact section, not full details
    assert django_finding["description"] == "An issue was discovered in Django that allows XSS via the admin ForeignKeyRawIdWidget."
    django_vd = django_finding["vuln_details"]
    assert django_vd[0]["cvss"] == "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N"


def test_parse_ghsa_sections_with_sections():
    details = "### Impact\n\nThis is the impact.\n\n### Patches\n\nUpgrade to 1.0.1.\n\n### Proof of Concept\n\n```python\nexploit()\n```"
    sections = _parse_ghsa_sections(details)
    assert "impact" in sections
    assert sections["impact"] == "This is the impact."
    assert "patches" in sections
    assert "proof of concept" in sections
    desc = _build_description_from_sections(sections, details, "short summary")
    assert desc == "This is the impact."


def test_parse_ghsa_sections_no_sections():
    details = "Plain text with no markdown headers."
    assert _parse_ghsa_sections(details) == {}
    desc = _build_description_from_sections({}, details, "summary")
    assert desc == details


def test_parse_ghsa_sections_prefers_impact_over_details():
    details = "## Summary\n\nSummary text.\n\n## Impact\n\nImpact text.\n\n## Details\n\nDetails text."
    sections = _parse_ghsa_sections(details)
    desc = _build_description_from_sections(sections, details, "")
    assert desc == "Impact text."

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

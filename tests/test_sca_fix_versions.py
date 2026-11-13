import pytest

from gerion_cli.tools.parser import compare_versions, parse_sca_tool_output


def _affected(name, *ranges, ecosystem="npm"):
    return {
        "package": {"name": name, "ecosystem": ecosystem},
        "ranges": [{"type": rtype, "events": events} for rtype, events in ranges],
    }


def _osv_output(name, version, vulns, ecosystem="npm"):
    return [{
        "source": {"path": "/repo/package-lock.json", "type": "lockfile"},
        "packages": [{
            "package": {"name": name, "version": version, "ecosystem": ecosystem},
            "vulnerabilities": vulns,
        }],
    }]


def _branch_vuln(vid, *fixes, name="undici", ecosystem="npm"):
    """One affected entry per maintained branch, like real GHSA advisories."""
    return {
        "id": vid,
        "aliases": [],
        "affected": [
            _affected(name, ("ECOSYSTEM", [{"introduced": f"{fix.split('.')[0]}.0.0"}, {"fixed": fix}]), ecosystem=ecosystem)
            for fix in fixes
        ],
    }


def test_multi_branch_advisory_is_not_dropped(mock_metadata):
    # Real case (undici 8.11.2 in a package-lock.json, osv-scanner 2.7.0): every advisory
    # lists the 6.x and 7.x branch fixes first. The parser used to pick 6.29.1, conclude
    # 8.11.2 >= fix and silently drop the vulnerable package.
    vulns = [
        _branch_vuln("GHSA-2m5v-pch6-74hx", "6.29.1", "7.30.1", "8.12.2"),
        _branch_vuln("GHSA-4w7w-5xrc-9h26", "7.30.1", "8.12.2"),
    ]
    findings = parse_sca_tool_output(_osv_output("undici", "8.11.2", vulns), mock_metadata)

    assert len(findings) == 1
    finding = findings[0]
    assert finding["component_fix"] == "8.12.2"
    assert [vd["fixed"] for vd in finding["vuln_details"]] == ["8.12.2", "8.12.2"]
    assert "Fixes all 2 vulnerabilities" in finding["mitigation"]


def test_component_fix_is_max_of_per_vuln_minimal_fixes(mock_metadata):
    vulns = [
        _branch_vuln("V-1", "3.2.20", "4.1.10", "4.2.3", name="django", ecosystem="PyPI"),
        _branch_vuln("V-2", "3.2.25", "4.2.11", "5.0.3", name="django", ecosystem="PyPI"),
    ]
    output = _osv_output("django", "4.2.1", vulns, ecosystem="PyPI")
    finding = parse_sca_tool_output(output, mock_metadata)[0]

    assert finding["component_fix"] == "4.2.11"
    assert sorted(vd["fixed"] for vd in finding["vuln_details"]) == ["4.2.11", "4.2.3"]


def test_package_with_some_unfixed_vulns_is_reported(mock_metadata):
    vulns = [
        _branch_vuln("V-FIXED", "2.0.0", name="lib"),
        {"id": "V-OPEN", "affected": [_affected("lib", ("SEMVER", [{"introduced": "0"}, {"last_affected": "9.9.9"}]))]},
    ]
    finding = parse_sca_tool_output(_osv_output("lib", "1.0.0", vulns), mock_metadata)[0]

    assert finding["component_fix"] == "2.0.0"
    assert "1 of 2 vulnerabilities have no known fix" in finding["mitigation"]


def test_reported_package_without_applicable_fix_is_kept(mock_metadata):
    # OSV is the authority on "vulnerable"; a fix at or below the installed version
    # (another branch) is not applicable and must not hide the finding.
    vulns = [_branch_vuln("V-1", "1.5.0", name="lib")]
    findings = parse_sca_tool_output(_osv_output("lib", "2.0.0", vulns), mock_metadata)

    assert len(findings) == 1
    assert findings[0]["component_fix"] is None
    assert "No known fix available" in findings[0]["mitigation"]


def test_git_ranges_are_ignored(mock_metadata):
    vuln = {
        "id": "PYSEC-X",
        "affected": [_affected(
            "fastapi",
            # A commit hash with a numeric prefix would otherwise look like version 9.
            ("GIT", [{"introduced": "0"}, {"fixed": "9d34ad0ee8a0dfbbcce06f76c2d5d851085024fc"}]),
            ("ECOSYSTEM", [{"introduced": "0"}, {"fixed": "0.109.1"}]),
            ecosystem="PyPI",
        )],
    }
    output = _osv_output("fastapi", "0.95.0", [vuln], ecosystem="PyPI")
    assert parse_sca_tool_output(output, mock_metadata)[0]["component_fix"] == "0.109.1"


def test_aliased_records_count_once(mock_metadata):
    vulns = [
        {**_branch_vuln("PYSEC-1", "2.0.0", name="lib"), "aliases": ["CVE-2024-1"]},
        {**_branch_vuln("GHSA-1", "2.0.0", name="lib"), "aliases": ["CVE-2024-1"]},
    ]
    finding = parse_sca_tool_output(_osv_output("lib", "1.0.0", vulns), mock_metadata)[0]

    assert finding["cve"] == ["CVE-2024-1"]
    assert finding["mitigation"].endswith("Fixes all 1 vulnerabilities.")


def test_non_pep440_versions(mock_metadata):
    vulns = [_branch_vuln("V-1", "1.2.4.Final", name="org.example:lib", ecosystem="Maven")]
    output = _osv_output("org.example:lib", "1.2.3.Final", vulns, ecosystem="Maven")
    assert parse_sca_tool_output(output, mock_metadata)[0]["component_fix"] == "1.2.4.Final"


@pytest.mark.parametrize(("a", "b", "expected"), [
    ("1.2.3", "1.2.10", -1),
    ("v1.2.3", "1.2.3", 0),
    ("1.2.3.Final", "1.2.4.Final", -1),
    ("1.2.3-SNAPSHOT", "1.2.3", 0),
    ("2.0.0-beta.1", "2.0.0", -1),
    ("1.2", "1.2.0", 0),
    ("2019.11.28", "2023.07.22", -1),
    ("abc", "1.0.0", None),
])
def test_compare_versions(a, b, expected):
    assert compare_versions(a, b) == expected


def test_malicious_package_record_is_critical(mock_metadata):
    """OSV MAL-* records have no severity; they used to fall through to LOW."""
    mal = {
        "id": "MAL-2025-6812",
        "aliases": [],
        "summary": "Malicious code in eslint-plugin-react_editor (npm)",
        "database_specific": {"malicious-packages-origins": [{"source": "ossf-package-analysis"}]},
        "affected": [_affected("eslint-plugin-react_editor", ("ECOSYSTEM", [{"introduced": "0"}]))],
    }
    findings = parse_sca_tool_output(_osv_output("eslint-plugin-react_editor", "71.71.72", [mal]), mock_metadata)
    assert [f["severity"] for f in findings] == ["CRITICAL"]

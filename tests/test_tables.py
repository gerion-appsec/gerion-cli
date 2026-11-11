import pytest

from gerion_cli.commands.report import display_text_report
from gerion_cli.output.tables import findings_table

# Titles, paths and texts come from scanned repositories and scanner output.
HOSTILE = {
    "finding_id": "id1",
    "severity": "HIGH",
    "title": "[bold]t[/]",
    "file_path": "src/[/red].py",
    "line_number": 3,
    "description": "x [/dim] y",
    "mitigation": "[link=http://evil]m[/link]",
    "cve": ["[/b]CVE"],
    "component_name": "[i]pkg",
    "component_version": "1.0",
    "scan_type": "SAST",
}


@pytest.mark.parametrize("scan_type", ["Secrets", "SAST", "IaC", "SCA"])
def test_findings_table_renders_markup_literally(scan_type, capsys):
    findings_table([dict(HOSTILE)], scan_type)
    out = capsys.readouterr().out
    assert "[/red]" in out or "[/b]" in out


def test_iac_table_handles_missing_mitigation(capsys):
    findings_table([{**HOSTILE, "mitigation": None, "severity": None}], "IaC")
    assert "N/A" in capsys.readouterr().out


def test_text_report_renders_markup_literally(capsys):
    display_text_report([dict(HOSTILE)], "repo[/x]", "main", True, True, False)
    out = capsys.readouterr().out
    assert "[/dim]" in out
    assert "repo[/x]" in out

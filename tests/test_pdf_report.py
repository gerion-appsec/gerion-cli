import warnings

from gerion_cli.commands.report import generate_pdf_report

FINDINGS = [
    {
        "finding_id": f"F-{i}",
        "title": f"Finding {i}",
        "description": "Some description " * 20,
        "mitigation": "Apply the fix",
        "severity": severity,
        "scan_type": scan_type,
        "file_path": "src/app/module.py",
        "line_number": i * 10,
        "status": "open",
    }
    for i, (severity, scan_type) in enumerate(
        [("CRITICAL", "sast"), ("HIGH", "sca"), ("MEDIUM", "secrets"), ("LOW", "iac")], start=1
    )
]


def test_pdf_report_is_generated_without_deprecations(tmp_path):
    output = tmp_path / "report.pdf"
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        generate_pdf_report(FINDINGS, "repo", "main", str(output), True, True, False)
    assert output.read_bytes().startswith(b"%PDF")


def test_unknown_severities_are_bucketed():
    from gerion_cli.commands.report import severity_stats

    stats = severity_stats([{"severity": "high"}, {"severity": "BLOCKER"}, {"severity": None}, {}])
    assert list(stats) == ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]
    assert stats["HIGH"] == 1
    assert stats["UNKNOWN"] == 3


def test_pdf_with_unknown_severities_is_generated(tmp_path):
    output = tmp_path / "report.pdf"
    findings = [{**FINDINGS[0], "severity": "BLOCKER"}, {**FINDINGS[1], "severity": None}]
    generate_pdf_report(findings, "repo", "main", str(output), True, True, True)
    assert output.read_bytes().startswith(b"%PDF")


def test_pdf_error_has_no_traceback_at_info_level(tmp_path, capsys):
    import pytest
    import typer

    with pytest.raises(typer.Abort):
        generate_pdf_report(FINDINGS, "repo", "main", str(tmp_path / "missing" / "r.pdf"), True, True, True)
    captured = capsys.readouterr()
    assert "Error generating PDF report" in captured.err
    assert "Traceback" not in captured.out + captured.err

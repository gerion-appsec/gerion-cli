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

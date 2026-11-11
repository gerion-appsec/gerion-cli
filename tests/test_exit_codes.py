import importlib
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from gerion_cli.commands.base import count_findings_at_or_above
from gerion_cli.core import FailOn
from gerion_cli.main import app
from gerion_cli.tools import ToolError

secrets_module = importlib.import_module("gerion_cli.commands.secrets_scan")
scan_all_module = importlib.import_module("gerion_cli.commands.scan_all")

runner = CliRunner()
API = ["--api-url", "https://api.example.com", "--api-key", "secret"]


def _ok_runner(code_path, timeout):
    return [{"id": "x"}]


def _failing_runner(code_path, timeout):
    raise ToolError("scanner exploded")


def _parser_for(severity):
    def parser(output, metadata):
        return [{"finding_id": item["id"], "scan_type": metadata["scan_type"], "severity": severity,
                 "title": "t", "file_path": "f", "line_number": 1} for item in output]
    return parser


def _configs(spec):
    """spec: list of (scan_type, runner, severity)."""
    return [
        {"scan_type": name, "tool_name": name, "tool_runner": run, "tool_parser": _parser_for(sev)}
        for name, run, sev in spec
    ]


@pytest.fixture
def patch_secrets(monkeypatch):
    def apply(run=_ok_runner, severity="HIGH"):
        monkeypatch.setattr(secrets_module, "run_secrets_tool", run)
        monkeypatch.setattr(secrets_module, "parse_secrets_tool_output", _parser_for(severity))
    return apply


# --- Item 4: failed upload ---

def test_failed_upload_exits_4_and_keeps_table(patch_secrets, tmp_path):
    patch_secrets()
    with patch("gerion_cli.api.send_to_api", return_value=False):
        result = runner.invoke(app, ["secrets-scan", str(tmp_path), *API])
    assert result.exit_code == 4
    assert "could not be uploaded" in result.output
    assert "Results will be displayed in console only" in result.output


def test_successful_upload_exits_0(patch_secrets, tmp_path):
    patch_secrets()
    with patch("gerion_cli.api.send_to_api", return_value=True):
        assert runner.invoke(app, ["secrets-scan", str(tmp_path), *API]).exit_code == 0


def test_console_mode_without_credentials_exits_0(patch_secrets, tmp_path, monkeypatch):
    monkeypatch.delenv("GERION_API_KEY", raising=False)
    monkeypatch.delenv("GERION_API_URL", raising=False)
    patch_secrets()
    assert runner.invoke(app, ["secrets-scan", str(tmp_path)]).exit_code == 0


def test_scan_all_uploads_every_scan_and_exits_4_listing_failed_uploads(monkeypatch, tmp_path):
    monkeypatch.setattr(scan_all_module, "SCAN_CONFIGS", _configs([
        ("Secrets", _ok_runner, "HIGH"), ("SCA", _ok_runner, "HIGH"), ("IaC", _ok_runner, "HIGH"),
    ]))
    sent = []

    def fake_send(results, *args):
        sent.append(results["metadata"]["scan_type"])
        return results["metadata"]["scan_type"] != "SCA"

    with patch("gerion_cli.api.send_to_api", side_effect=fake_send):
        result = runner.invoke(app, ["scan-all", str(tmp_path), *API])
    assert result.exit_code == 4
    assert sent == ["Secrets", "SCA", "IaC"]
    assert "Failed uploads: SCA" in result.output


# --- Item 6: --fail-on ---

@pytest.mark.parametrize("severity, threshold, expected", [
    ("CRITICAL", "critical", 1), ("HIGH", "critical", 0), ("high", "high", 1), ("High", "high", 1),
    ("MEDIUM", "high", 0), ("MEDIUM", "medium", 1), ("LOW", "medium", 0), ("LOW", "low", 1),
    ("INFO", "low", 1), ("weird", "low", 1), (None, "low", 1), ("", "medium", 0), (None, "high", 0),
])
def test_count_findings_at_or_above(severity, threshold, expected):
    assert count_findings_at_or_above([{"severity": severity}], FailOn(threshold)) == expected


def test_fail_on_exits_3_after_output_when_threshold_met(patch_secrets, tmp_path):
    patch_secrets(severity="HIGH")
    result = runner.invoke(app, ["secrets-scan", str(tmp_path), "--fail-on", "high", "--format", "json"])
    assert result.exit_code == 3
    assert "1 finding(s) with severity HIGH or higher" in result.output
    assert '"finding_id"' in result.output  # results were still emitted


def test_fail_on_is_case_insensitive_and_reads_env(patch_secrets, tmp_path, monkeypatch):
    patch_secrets(severity="MEDIUM")
    assert runner.invoke(app, ["secrets-scan", str(tmp_path), "--fail-on", "HIGH"]).exit_code == 0
    monkeypatch.setenv("GERION_FAIL_ON", "medium")
    assert runner.invoke(app, ["secrets-scan", str(tmp_path)]).exit_code == 3


def test_no_fail_on_never_fails_on_findings(patch_secrets, tmp_path, monkeypatch):
    monkeypatch.delenv("GERION_FAIL_ON", raising=False)
    patch_secrets(severity="CRITICAL")
    assert runner.invoke(app, ["secrets-scan", str(tmp_path)]).exit_code == 0


def test_fail_on_below_threshold_reports_and_exits_0(patch_secrets, tmp_path):
    patch_secrets(severity="LOW")
    result = runner.invoke(app, ["secrets-scan", str(tmp_path), "--fail-on", "critical"])
    assert result.exit_code == 0
    assert "No findings with severity CRITICAL or higher" in result.output


def test_scanner_failure_wins_over_fail_on(patch_secrets, tmp_path):
    patch_secrets(run=_failing_runner)
    assert runner.invoke(app, ["secrets-scan", str(tmp_path), "--fail-on", "low"]).exit_code == 1


def test_fail_on_wins_over_upload_failure(patch_secrets, tmp_path):
    patch_secrets(severity="CRITICAL")
    with patch("gerion_cli.api.send_to_api", return_value=False):
        result = runner.invoke(app, ["secrets-scan", str(tmp_path), "--fail-on", "low", *API])
    assert result.exit_code == 3
    assert "could not be uploaded" in result.output


@pytest.mark.parametrize("command", ["secrets-scan", "sca-scan", "iac-scan", "sast-scan", "scan-all"])
def test_every_scan_command_has_fail_on(command):
    result = runner.invoke(app, [command, "--help"])
    assert "--fail-on" in result.output
    assert "GERION_FAIL_ON" in result.output


def test_invalid_fail_on_is_a_usage_error(tmp_path):
    assert runner.invoke(app, ["secrets-scan", str(tmp_path), "--fail-on", "bogus"]).exit_code == 2


def test_scan_all_fail_on_aggregates_completed_scans(monkeypatch, tmp_path):
    monkeypatch.setattr(scan_all_module, "SCAN_CONFIGS", _configs([
        ("Secrets", _ok_runner, "LOW"), ("SCA", _ok_runner, "MEDIUM"), ("IaC", _ok_runner, "HIGH"),
    ]))
    out = tmp_path / "all.json"
    base = ["scan-all", str(tmp_path), "--output-file", str(out)]
    assert runner.invoke(app, [*base, "--fail-on", "critical"]).exit_code == 0
    result = runner.invoke(app, [*base, "--fail-on", "high"])
    assert result.exit_code == 3
    assert "1 finding(s) with severity HIGH or higher" in result.output
    assert out.exists()
    assert runner.invoke(app, [*base, "--fail-on", "low"]).exit_code == 3


def test_scan_all_scanner_failure_wins_over_fail_on(monkeypatch, tmp_path):
    monkeypatch.setattr(scan_all_module, "SCAN_CONFIGS", _configs([
        ("Secrets", _ok_runner, "CRITICAL"), ("SCA", _failing_runner, "LOW"),
    ]))
    result = runner.invoke(app, ["scan-all", str(tmp_path), "--fail-on", "low"])
    assert result.exit_code == 1
    assert "finding(s) with severity LOW or higher" in result.output


def test_scan_all_fail_on_wins_over_upload_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(scan_all_module, "SCAN_CONFIGS", _configs([("Secrets", _ok_runner, "CRITICAL")]))
    with patch("gerion_cli.api.send_to_api", return_value=False):
        result = runner.invoke(app, ["scan-all", str(tmp_path), "--fail-on", "low", *API])
    assert result.exit_code == 3
    assert "Failed uploads: Secrets" in result.output


@pytest.mark.parametrize("sequential", [False, True])
@pytest.mark.parametrize("scan_failed, gate_met, upload_failed, expected", [
    (False, False, False, 0),
    (False, False, True, 4),
    (False, True, False, 3),
    (False, True, True, 3),
    (True, False, False, 1),
    (True, False, True, 1),
    (True, True, False, 1),
    (True, True, True, 1),
])
def test_scan_all_exit_precedence(monkeypatch, tmp_path, sequential, scan_failed, gate_met, upload_failed, expected):
    configs = _configs([("Secrets", _ok_runner, "HIGH" if gate_met else "LOW")])
    if scan_failed:
        configs += _configs([("SCA", _failing_runner, "LOW")])
    monkeypatch.setattr(scan_all_module, "SCAN_CONFIGS", configs)
    args = ["scan-all", str(tmp_path), "--fail-on", "high", *API]
    if sequential:
        args.append("--sequential")
    with patch("gerion_cli.api.send_to_api", return_value=not upload_failed) as send:
        result = runner.invoke(app, args)
    assert result.exit_code == expected
    assert send.call_count == 1
    if scan_failed:
        assert "scanner exploded" in result.output
    if gate_met:
        assert "1 finding(s) with severity HIGH or higher" in result.output
    if upload_failed:
        assert "Failed uploads: Secrets" in result.output


def test_authentication_failure_exits_4(patch_secrets, tmp_path):
    patch_secrets()
    with patch("gerion_cli.api.client._get_token", return_value=None):
        result = runner.invoke(app, ["secrets-scan", str(tmp_path), *API])
    assert result.exit_code == 4
    assert "Failed to authenticate" in result.output


@pytest.mark.parametrize("stage", ["runner", "parser"])
def test_unexpected_scan_error_exits_1(patch_secrets, tmp_path, monkeypatch, stage):
    patch_secrets()

    def unexpected(*args, **kwargs):
        raise RuntimeError("unexpected scanner error")

    name = "run_secrets_tool" if stage == "runner" else "parse_secrets_tool_output"
    monkeypatch.setattr(secrets_module, name, unexpected)
    result = runner.invoke(app, ["secrets-scan", str(tmp_path), "--fail-on", "low", *API])
    assert result.exit_code == 1

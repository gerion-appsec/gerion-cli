import importlib
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

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

def test_failed_upload_exits_1_and_keeps_table(patch_secrets, tmp_path):
    patch_secrets()
    with patch("gerion_cli.api.send_to_api", return_value=False):
        result = runner.invoke(app, ["secrets-scan", str(tmp_path), *API])
    assert result.exit_code == 1
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


def test_scan_all_uploads_every_scan_and_exits_1_listing_failed_uploads(monkeypatch, tmp_path):
    monkeypatch.setattr(scan_all_module, "SCAN_CONFIGS", _configs([
        ("Secrets", _ok_runner, "HIGH"), ("SCA", _ok_runner, "HIGH"), ("IaC", _ok_runner, "HIGH"),
    ]))
    sent = []

    def fake_send(results, *args):
        sent.append(results["metadata"]["scan_type"])
        return results["metadata"]["scan_type"] != "SCA"

    with patch("gerion_cli.api.send_to_api", side_effect=fake_send):
        result = runner.invoke(app, ["scan-all", str(tmp_path), *API])
    assert result.exit_code == 1
    assert sent == ["Secrets", "SCA", "IaC"]
    assert "Failed uploads: SCA" in result.output

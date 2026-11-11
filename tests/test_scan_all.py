import importlib
import json

import pytest
import typer

from gerion_cli.tools import ToolError

# gerion_cli.commands re-exports the scan_all function under the module's name.
scan_all_module = importlib.import_module("gerion_cli.commands.scan_all")


def _failing_runner(code_path, timeout):
    raise ToolError("scanner exploded")


def _ok_runner(code_path, timeout):
    return [{"id": "x"}]


def _parser(output, metadata):
    return [{"finding_id": item["id"], "scan_type": metadata["scan_type"], "severity": "HIGH"} for item in output]


def test_scan_all_runs_every_scan_and_exits_1(tmp_path, monkeypatch):
    configs = [
        {"scan_type": "Secrets", "tool_name": "A", "tool_runner": _ok_runner, "tool_parser": _parser},
        {"scan_type": "SCA", "tool_name": "B", "tool_runner": _failing_runner, "tool_parser": _parser},
        {"scan_type": "IaC", "tool_name": "C", "tool_runner": _ok_runner, "tool_parser": _parser},
    ]
    monkeypatch.setattr(scan_all_module, "SCAN_CONFIGS", configs)
    output_file = tmp_path / "all.sarif"

    with pytest.raises(typer.Exit) as exc_info:
        scan_all_module.scan_all(
            code_path=".", api_url=None, client_id=None, api_key=None,
            output_file=str(output_file), format=None, timeout=5, log_level="info",
        )

    assert exc_info.value.exit_code == 1
    data = json.loads(output_file.read_text())
    # Format inferred from the extension, like single scans; partial results are kept.
    assert data["version"] == "2.1.0"
    assert len(data["runs"][0]["results"]) == 2

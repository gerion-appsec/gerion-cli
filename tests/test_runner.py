import os
import stat

import pytest
import typer

from gerion_cli.commands.base import run_scan
from gerion_cli.core.types import OutputFormat
from gerion_cli.output.formats import resolve_file_format
from gerion_cli.tools import run_sca_tool
from gerion_cli.tools._runner import ToolError, output_tail, run_tool

FAKE_TOOL = """#!/bin/sh
# Fake scanner: the report path is the --output-file value, else $1.
# Behaviour comes from the environment.
report="$1"; prev=""
for arg in "$@"; do [ "$prev" = "--output-file" ] && report="$arg"; prev="$arg"; done
echo "fake progress output" >&2
if [ -n "$FAKE_SLEEP" ]; then sleep "$FAKE_SLEEP"; fi
if [ -n "$FAKE_REPORT" ]; then printf '%s' "$FAKE_REPORT" > "$report"; fi
echo "$report" > "$FAKE_SEEN"
exit "${FAKE_EXIT:-0}"
"""


@pytest.fixture
def fake_tool(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    script = bin_dir / "faketool"
    script.write_text(FAKE_TOOL)
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("FAKE_SEEN", str(tmp_path / "seen"))
    for var in ("FAKE_EXIT", "FAKE_REPORT", "FAKE_SLEEP"):
        monkeypatch.delenv(var, raising=False)
    return tmp_path


def _run(**kwargs):
    return run_tool("faketool", lambda report_path: ["faketool", report_path], timeout=5, **kwargs)


def test_returns_parsed_report_and_removes_it(fake_tool, monkeypatch):
    monkeypatch.setenv("FAKE_REPORT", '[{"Secret": "raw"}]')
    assert _run() == [{"Secret": "raw"}]

    report_path = (fake_tool / "seen").read_text().strip()
    assert not os.path.exists(report_path)
    assert not os.path.exists(os.path.dirname(report_path))


def test_missing_binary_raises():
    with pytest.raises(ToolError, match="not found in PATH"):
        run_tool("gerion-no-such-tool", lambda report_path: ["gerion-no-such-tool"], timeout=5)


def test_unexpected_exit_code_raises_with_output_tail(fake_tool, monkeypatch):
    monkeypatch.setenv("FAKE_EXIT", "127")
    monkeypatch.setenv("FAKE_REPORT", "{}")  # osv-scanner writes a partial report when offline
    with pytest.raises(ToolError, match="exit code 127: fake progress output"):
        _run()


def test_no_report_exit_code_returns_none(fake_tool, monkeypatch):
    monkeypatch.setenv("FAKE_EXIT", "128")
    assert _run(no_report_exit_codes=(128,)) is None


def test_missing_report_raises(fake_tool):
    with pytest.raises(ToolError, match="wrote no report"):
        _run()


def test_invalid_report_raises(fake_tool, monkeypatch):
    monkeypatch.setenv("FAKE_REPORT", "{not json")
    with pytest.raises(ToolError, match="invalid JSON"):
        _run()


def test_timeout_raises(fake_tool, monkeypatch):
    monkeypatch.setenv("FAKE_SLEEP", "5")
    with pytest.raises(ToolError, match="timed out"):
        run_tool("faketool", lambda report_path: ["faketool", report_path], timeout=1)


def test_output_tail_strips_escapes_and_truncates():
    assert output_tail("\x1b[31mERR\x1b[0m boom\x07") == "ERR boom"
    assert output_tail("x" * 600) == "..." + "x" * 500


@pytest.mark.parametrize(("exit_code", "report", "expected"), [
    ("0", '{"results": []}', []),
    ("1", '{"results": [{"packages": []}]}', [{"packages": []}]),
    ("128", "", []),
])
def test_osv_exit_codes(fake_tool, monkeypatch, exit_code, report, expected):
    (fake_tool / "bin" / "osv-scanner").symlink_to(fake_tool / "bin" / "faketool")
    monkeypatch.setenv("FAKE_EXIT", exit_code)
    if report:
        monkeypatch.setenv("FAKE_REPORT", report)
    assert run_sca_tool(str(fake_tool)) == expected


def _failing_runner(code_path, timeout):
    raise ToolError("scanner exploded")


def _ok_runner(code_path, timeout):
    return [{"id": "x"}]


def _parser(output, metadata):
    return [{"finding_id": item["id"], "scan_type": metadata["scan_type"], "severity": "HIGH"} for item in output]


def _scan_kwargs(**overrides):
    kwargs = {
        "scan_type": "Secrets", "tool_name": "Fake", "tool_runner": _failing_runner, "tool_parser": _parser,
        "code_path": ".", "api_url": None, "client_id": None, "api_key": None, "output_file": None,
        "format": OutputFormat.JSON, "timeout": 5, "log_level": "info",
    }
    kwargs.update(overrides)
    return kwargs


def test_run_scan_exits_1_when_tool_fails(capsys):
    with pytest.raises(typer.Exit) as exc_info:
        run_scan(**_scan_kwargs())
    assert exc_info.value.exit_code == 1
    assert "No security findings" not in capsys.readouterr().out


@pytest.mark.parametrize(("filename", "explicit", "expected"), [
    ("out.sarif", None, OutputFormat.SARIF),
    ("out.MD", None, OutputFormat.MARKDOWN),
    ("out.txt", None, OutputFormat.JSON),
    ("out.sarif", OutputFormat.JSON, OutputFormat.JSON),
    ("out.sarif", OutputFormat.TABLE, OutputFormat.SARIF),
])
def test_resolve_file_format(filename, explicit, expected):
    assert resolve_file_format(filename, explicit) == expected


@pytest.mark.parametrize(("module", "runner"), [
    ("secrets", "run_secrets_tool"), ("sca", "run_sca_tool"), ("iac", "run_iac_tool"), ("sast", "run_sast_tool"),
])
def test_code_path_starting_with_dash_is_not_an_option(monkeypatch, module, runner):
    """`gerion secrets-scan -- -v` ran `gitleaks dir -v`: verbose mode on the wrong directory."""
    import importlib

    tool_module = importlib.import_module(f"gerion_cli.tools.{module}")
    argvs = []

    def fake_run_tool(tool, build_command, **kwargs):
        argvs.append(build_command("/tmp/report.json"))
        return [] if module == "secrets" else {}

    monkeypatch.setattr(tool_module, "run_tool", fake_run_tool)
    getattr(tool_module, runner)("-v", timeout=5)

    assert "-v" not in argvs[0]
    assert os.path.join(".", "-v") in argvs[0]

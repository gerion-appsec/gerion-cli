import importlib
import json
import os
import signal
import stat
import subprocess
import sys
import time

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
            output_file=str(output_file), format=None, timeout=5, sequential=False, log_level="info",
        )

    assert exc_info.value.exit_code == 1
    data = json.loads(output_file.read_text())
    # Format inferred from the extension, like single scans; partial results are kept.
    assert data["version"] == "2.1.0"
    assert len(data["runs"][0]["results"]) == 2


def _sleepy_runner(delay, record):
    def runner(code_path, timeout):
        record["active"] += 1
        record["max_active"] = max(record["max_active"], record["active"])
        time.sleep(delay)
        record["active"] -= 1
        return [{"id": f"x{delay}"}]
    return runner


def _sleepy_configs(record):
    # The first scanner finishes last when run concurrently.
    return [
        {"scan_type": scan_type, "tool_name": scan_type, "tool_runner": _sleepy_runner(delay, record), "tool_parser": _parser}
        for scan_type, delay in (("Secrets", 0.4), ("SCA", 0.3), ("IaC", 0.2), ("SAST", 0.1))
    ]


@pytest.mark.parametrize("sequential", [False, True])
def test_scan_all_parallel_keeps_fixed_order_and_wall_clock_duration(tmp_path, monkeypatch, sequential):
    record = {"active": 0, "max_active": 0}
    monkeypatch.setattr(scan_all_module, "SCAN_CONFIGS", _sleepy_configs(record))
    metadata_calls = []
    real_get_metadata = scan_all_module.get_metadata
    monkeypatch.setattr(scan_all_module, "get_metadata", lambda **kw: metadata_calls.append(kw) or real_get_metadata(**kw))
    output_file = tmp_path / "all.json"

    scan_all_module.scan_all(
        code_path=str(tmp_path), api_url=None, client_id=None, api_key=None,
        output_file=str(output_file), format=None, timeout=5, sequential=sequential, log_level="info",
    )

    data = json.loads(output_file.read_text())
    assert [f["scan_type"] for f in data["findings"]] == ["Secrets", "SCA", "IaC", "SAST"]
    assert len(metadata_calls) == 1
    duration = data["metadata"]["scan_duration"]
    if sequential:
        assert record["max_active"] == 1
        assert duration >= 1.0
    else:
        assert record["max_active"] > 1
        assert duration < 0.9  # wall clock, not the 1.0 s sum of the four scans


def test_scan_all_keeps_each_scan_duration(monkeypatch, tmp_path):
    record = {"active": 0, "max_active": 0}
    monkeypatch.setattr(scan_all_module, "SCAN_CONFIGS", _sleepy_configs(record))
    built = []
    real_build = scan_all_module.build_results
    monkeypatch.setattr(scan_all_module, "build_results", lambda *a: built.append(a[3]) or real_build(*a))

    scan_all_module.scan_all(
        code_path=str(tmp_path), api_url=None, client_id=None, api_key=None,
        output_file=str(tmp_path / "all.json"), format=None, timeout=5, sequential=False, log_level="info",
    )

    durations = {metadata["scan_type"]: metadata["scan_duration"] for metadata in built}
    assert durations["Secrets"] >= 0.4 > durations["SAST"] >= 0.1


SLOW_SCANNER = """#!/bin/sh
sleep 30 &
echo "$!" > "$FAKE_PID_DIR/$(basename "$0")"
wait
"""


@pytest.mark.parametrize("sig", [signal.SIGINT, signal.SIGTERM])
def test_interrupted_scan_all_kills_every_scanner(tmp_path, sig):
    """Ctrl-C / SIGTERM must stop the parallel scanners promptly and leave no process behind."""
    if not os.path.isdir("/proc"):
        pytest.skip("needs /proc")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    pid_dir = tmp_path / "pids"
    pid_dir.mkdir()
    for tool in ("gitleaks", "osv-scanner", "kics", "opengrep"):
        script = bin_dir / tool
        script.write_text(SLOW_SCANNER)
        script.chmod(script.stat().st_mode | stat.S_IXUSR)
    env = {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}", "FAKE_PID_DIR": str(pid_dir)}

    cli = subprocess.Popen(
        [sys.executable, "-c", "from gerion_cli.main import app; app()", "scan-all", str(tmp_path), "--format", "json"],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + 10
    while len(list(pid_dir.iterdir())) < 4 and time.monotonic() < deadline:
        time.sleep(0.05)
    assert len(list(pid_dir.iterdir())) == 4, "the four scanners did not start concurrently"

    started = time.monotonic()
    cli.send_signal(sig)
    assert cli.wait(timeout=5) != 0
    assert time.monotonic() - started < 3

    for pid_file in pid_dir.iterdir():
        _assert_gone(int(pid_file.read_text()))


def _assert_gone(pid):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        try:
            with open(f"/proc/{pid}/stat") as f:
                if f.read().split(")")[-1].split()[0] == "Z":
                    return
        except FileNotFoundError:
            return
        time.sleep(0.05)
    raise AssertionError(f"scanner child {pid} is still running")

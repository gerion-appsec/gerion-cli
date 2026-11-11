"""
Shared execution of the external scanners.

Every failure raises ToolError: a scanner that did not run must never look like a
clean scan.
"""
import json
import re
import shutil
import subprocess
import tempfile
from collections.abc import Callable, Collection
from pathlib import Path
from typing import Any

OUTPUT_TAIL_CHARS = 500
# ANSI escape sequences and control characters (keeps \n and \t).
_UNSAFE_OUTPUT = re.compile(r'\x1b\[[0-9;?]*[ -/]*[@-~]|[\x00-\x08\x0b-\x1f\x7f]')


class ToolError(Exception):
    """A scanner could not run or did not complete; its result must not be trusted."""


def output_tail(output: str | None, limit: int = OUTPUT_TAIL_CHARS) -> str:
    """Last `limit` characters of scanner output, without terminal escape sequences."""
    text = _UNSAFE_OUTPUT.sub('', output or '').strip()
    if len(text) > limit:
        text = '...' + text[-limit:]
    return text


def run_tool(
    tool: str,
    build_command: Callable[[str], list[str]],
    timeout: int,
    ok_exit_codes: Collection[int] = (0,),
    no_report_exit_codes: Collection[int] = (),
) -> Any:
    """
    Run a scanner that writes a JSON report and return the parsed report.

    The report lives in a private temporary directory (mode 0700) that is removed on
    every exit path, so reports with raw secrets are never left behind.

    Args:
        tool: Executable name, resolved from PATH.
        build_command: Builds the argv from the report file path.
        timeout: Seconds before the scanner is killed.
        ok_exit_codes: Exit codes meaning the scan completed and wrote a report.
        no_report_exit_codes: Exit codes meaning "nothing to scan"; None is returned.

    Raises:
        ToolError: missing binary, timeout, unexpected exit code, missing or invalid report.
    """
    if not shutil.which(tool):
        raise ToolError(f"{tool} not found in PATH.")

    with tempfile.TemporaryDirectory(prefix="gerion-") as report_dir:
        report_path = Path(report_dir) / "report.json"
        command = build_command(str(report_path))
        try:
            process = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                errors="replace",
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise ToolError(f"{tool} timed out after {timeout} seconds.") from None
        except OSError as e:
            raise ToolError(f"{tool} could not be started: {e}") from e

        exit_code = process.returncode
        if exit_code in no_report_exit_codes:
            return None
        if exit_code not in ok_exit_codes:
            raise ToolError(f"{tool} failed with exit code {exit_code}: {output_tail(process.stdout)}")

        try:
            with open(report_path, encoding="utf-8") as report:
                return json.load(report)
        except FileNotFoundError:
            raise ToolError(f"{tool} exited with code {exit_code} but wrote no report.") from None
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise ToolError(f"{tool} wrote an invalid JSON report: {e}") from None

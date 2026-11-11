"""
IaC (Infrastructure as Code) scan tool integration.
"""
import os
import shutil
from typing import Any

from gerion_cli.tools._runner import ToolError, run_tool


def _kics_command(code_path: str, report_path: str, timeout: int, queries_path: str | None) -> list[str]:
    # KICS takes the report directory and the file name without extension separately.
    report_dir, report_file = os.path.split(report_path)
    command = [
        "kics", "scan",
        "--path", code_path,
        "--output-path", report_dir,
        "--output-name", os.path.splitext(report_file)[0],
        "--report-formats", "json",
        # Allow 10s buffer for CLI overhead
        "--timeout", str(max(1, timeout - 10)),
        "--ignore-on-exit", "results",  # Exit 0 even if findings found; errors still exit non-zero
        "--no-color",
        "--ci",
    ]

    # Priority:
    # 1. Explicitly passed queries_path
    # 2. auto-detection relative to binary
    if queries_path:
        command.extend(["--queries-path", queries_path])
    else:
        kics_bin_dir = os.path.dirname(os.path.realpath(shutil.which("kics") or "kics"))
        potential_queries_path = os.path.join(kics_bin_dir, 'assets', 'queries')
        if os.path.exists(potential_queries_path):
            command.extend(["--queries-path", potential_queries_path])
    return command


def run_iac_tool(code_path: str, timeout: int = 180, queries_path: str | None = None) -> list[dict[str, Any]]:
    """Run KICS and return its `queries` list. Raises ToolError on failure."""
    # With --ignore-on-exit results KICS exits 0 with or without findings and 126 on
    # engine errors (missing path, missing queries, ...).
    data = run_tool(
        "kics",
        lambda report_path: _kics_command(code_path, report_path, timeout, queries_path),
        timeout=timeout,
    )
    if not isinstance(data, dict):
        raise ToolError("kics wrote an unexpected report (expected a JSON object).")
    return data.get('queries') or []

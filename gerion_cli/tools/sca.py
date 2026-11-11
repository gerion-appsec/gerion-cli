"""
SCA (Software Component Analysis) tool integration.
"""
from typing import Any

from gerion_cli.tools._runner import ToolError, run_tool

# osv-scanner: 0 = no vulnerabilities, 1 = vulnerabilities found,
# 128 = no package sources found (no report written), 127 = error.
OSV_OK_EXIT_CODES = (0, 1)
OSV_NO_PACKAGES_EXIT_CODE = 128


def run_sca_tool(code_path: str, timeout: int = 180) -> list[dict[str, Any]]:
    """Run OSV-Scanner and return its `results` list. Raises ToolError on failure."""
    data = run_tool(
        "osv-scanner",
        lambda report_path: [
            "osv-scanner", "scan",
            "--no-resolve",
            "--format", "json",
            "--output-file", report_path,
            "-r",  # Recursive scan
            code_path,
        ],
        timeout=timeout,
        ok_exit_codes=OSV_OK_EXIT_CODES,
        no_report_exit_codes=(OSV_NO_PACKAGES_EXIT_CODE,),
    )
    if data is None:
        return []
    if not isinstance(data, dict):
        raise ToolError("osv-scanner wrote an unexpected report (expected a JSON object).")
    return data.get('results') or []

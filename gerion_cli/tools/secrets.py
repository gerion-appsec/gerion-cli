"""
Secrets detection tool integration.
"""
from typing import Any

from gerion_cli.tools._runner import ToolError, run_tool


def run_secrets_tool(code_path: str, timeout: int = 180) -> list[dict[str, Any]]:
    """Run Gitleaks and return its findings list. Raises ToolError on failure."""
    # --exit-code 0: leaks found is still exit 0; any other code is an error.
    data = run_tool(
        "gitleaks",
        lambda report_path: ["gitleaks", "dir", code_path, "--exit-code", "0", "-f", "json", "-r", report_path],
        timeout=timeout,
    )
    if not isinstance(data, list):
        raise ToolError("gitleaks wrote an unexpected report (expected a JSON list).")
    return data

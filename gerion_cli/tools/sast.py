from typing import Any

from gerion_cli.tools._runner import ToolError, path_arg, run_tool


def run_sast_tool(code_path: str, timeout: int = 180) -> list[dict[str, Any]]:
    """
    Run SAST scan using Opengrep.
    Findings are enriched by plugins if available.

    Returns:
        list: opengrep results. Raises ToolError on failure.
    """
    # Without --error, opengrep exits 0 with or without findings; non-zero is a
    # failure (e.g. 2 when the rules cannot be fetched or the path does not exist).
    data = run_tool(
        "opengrep",
        lambda report_path: [
            "opengrep", "scan",
            "--config", "auto",
            # Allow 10s buffer for CLI overhead
            "--timeout", str(max(1, timeout - 10)),
            "--json",
            "--output", report_path,
            "--disable-version-check",  # Optimization: skip version check for speed
            path_arg(code_path),
        ],
        timeout=timeout,
    )
    if not isinstance(data, dict):
        raise ToolError("opengrep wrote an unexpected report (expected a JSON object).")
    return data.get('results') or []

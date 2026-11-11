import time
from concurrent.futures import Future, ThreadPoolExecutor, wait
from typing import Any

import typer

from gerion_cli.commands.base import build_results, dispatch_results, execute_tool, write_output_file
from gerion_cli.core import (
    CLIENT_ID,
    LogLevel,
    OutputFormat,
    SecretString,
    error,
    get_metadata,
    info,
    panel,
    set_log_level,
)
from gerion_cli.output import findings_table, print_formatted
from gerion_cli.tools import (
    parse_iac_tool_output,
    parse_sast_tool_output,
    parse_sca_tool_output,
    parse_secrets_tool_output,
    run_iac_tool,
    run_sast_tool,
    run_sca_tool,
    run_secrets_tool,
)
from gerion_cli.tools._runner import kill_running_tools

SCAN_CONFIGS = [
    {"scan_type": "Secrets", "tool_name": "Gitleaks", "tool_runner": run_secrets_tool, "tool_parser": parse_secrets_tool_output},
    {"scan_type": "SCA", "tool_name": "OSV-Scanner", "tool_runner": run_sca_tool, "tool_parser": parse_sca_tool_output},
    {"scan_type": "IaC", "tool_name": "KICS", "tool_runner": run_iac_tool, "tool_parser": parse_iac_tool_output},
    {"scan_type": "SAST", "tool_name": "Opengrep", "tool_runner": run_sast_tool, "tool_parser": parse_sast_tool_output},
]

def scan_all(
    code_path: str = typer.Argument(".", help="Path to the code directory to scan", show_default=True),
    api_url: str = typer.Option(None, "--api-url", "-a", envvar="GERION_API_URL", help="API Gateway URL for sending results"),
    client_id: str = typer.Option(None, "--client-id", "-i", envvar="GERION_CLIENT_ID", help=f"Client ID for API authentication (default: {CLIENT_ID})"),
    api_key: str = typer.Option(None, "--api-key", "-k", envvar="GERION_API_KEY", hide_input=True, help="M2M API key for authentication"),
    output_file: str = typer.Option(None, "--output-file", "-o", help="Save aggregated results to a single file (disables API sending)"),
    format: OutputFormat = typer.Option(None, "--format", "-f", help="Output format for file saving or stdout (json, markdown, sarif)"),
    timeout: int = typer.Option(180, "--timeout", "-t", help="Tool execution timeout in seconds (per scan)"),
    sequential: bool = typer.Option(False, "--sequential", help="Run the scanners one after another instead of in parallel (lower peak CPU and memory)"),
    log_level: LogLevel = typer.Option(LogLevel.INFO, "--log-level", "-l", help="Set the logging level")
):
    """
    Run all security scans (Secrets, SCA, IaC, SAST).

    This command runs Gitleaks, OSV-Scanner, KICS, and Opengrep in parallel (one after
    another with --sequential). Results are always reported in that fixed order.
    When --output-file is provided, all findings are aggregated into a single file.
    When sending to API, each scan submits independently.
    Every scan runs even if another one fails; the command then exits with code 1.

    Examples:
        # Scan current directory with all tools
        gerion scan-all

        # Scan specific directory
        gerion scan-all /path/to/code

        # Save all results to a single file
        gerion scan-all --output-file results.json

        # Send to API Gateway
        gerion scan-all --api-url https://api.gerion.dev --api-key YOUR_KEY
    """
    set_log_level(log_level)
    api_key_string = SecretString.from_typer_option(api_key)
    effective_client_id = client_id or CLIENT_ID
    started = time.monotonic()

    # When output_file or format is set, individual scans only collect results —
    # scan_all handles aggregation and output at the end.
    aggregate_output = bool(output_file or format)

    base_metadata = get_metadata(code_path=code_path)
    completed: list[dict[str, Any]] = []
    failed: list[str] = []

    outcomes = _execute_scans(code_path, timeout, sequential)

    # Parse, enrich and emit in the fixed order, whatever order the scanners finished in.
    for config, outcome in zip(SCAN_CONFIGS, outcomes, strict=True):
        results = _build_one_scan(config, outcome, code_path, base_metadata)
        if results is None:
            failed.append(config["scan_type"])
            continue
        completed.append(results)
        if not aggregate_output:
            dispatch_results(results, config["scan_type"], api_url, effective_client_id, api_key_string, None, None)

    all_findings = [finding for results in completed for finding in results['findings']]
    total_duration = round(time.monotonic() - started, 2)

    # Aggregated output routing (mirrors base.py priority for individual scans).
    # Partial results are still emitted; the exit code reports the failed scans.
    if aggregate_output and completed:
        aggregated = {
            'metadata': {**base_metadata, 'scan_type': 'All', 'scan_duration': total_duration},
            'findings': all_findings
        }

        if output_file:
            write_output_file(aggregated, output_file, format)
            info(f"Aggregated results saved to {output_file}")
        elif format == OutputFormat.TABLE:
            findings_table(all_findings, "All")
        else:
            print_formatted(aggregated, format)

    succeeded = [results['metadata']['scan_type'] for results in completed]
    panel(
        "Full Scan Summary",
        f"Completed scans: {', '.join(succeeded) or 'none'}\n"
        f"Failed scans: {', '.join(failed) or 'none'}\n"
        f"Total findings: {len(all_findings)}\n"
        f"Total duration: {total_duration}s",
        "red" if failed else "green"
    )

    if failed:
        error(f"{len(failed)} of {len(SCAN_CONFIGS)} scans failed: {', '.join(failed)}. Their findings are missing.")
        raise typer.Exit(1)


def _run_scanner(config: dict[str, Any], code_path: str, timeout: int) -> tuple[Any, float] | Exception:
    """Run one scanner; its (raw output, duration), or the exception if it failed."""
    info(f"Starting {config['scan_type']} scan...")
    try:
        return execute_tool(config["tool_name"], config["tool_runner"], code_path, timeout)
    except Exception as e:
        return e


def _execute_scans(code_path: str, timeout: int, sequential: bool) -> list[tuple[Any, float] | Exception]:
    """Run every scanner, concurrently unless `sequential`; outcomes in SCAN_CONFIGS order."""
    if sequential:
        return [_run_scanner(config, code_path, timeout) for config in SCAN_CONFIGS]

    # The scanners are independent subprocesses: threads only wait on them.
    executor = ThreadPoolExecutor(max_workers=len(SCAN_CONFIGS), thread_name_prefix="gerion-scan")
    futures: list[Future] = []
    try:
        futures = [executor.submit(_run_scanner, config, code_path, timeout) for config in SCAN_CONFIGS]
        wait(futures)
        return [future.result() for future in futures]
    except BaseException:
        # Ctrl-C (or SIGTERM): the scanners run in their own sessions, so they must be
        # killed explicitly. Repeat until every worker is done, in case one was still
        # starting its scanner during the first pass.
        for future in futures:
            future.cancel()
        while not all(future.done() for future in futures):
            kill_running_tools()
            wait(futures, timeout=0.1)
        raise
    finally:
        executor.shutdown(wait=True, cancel_futures=True)


def _build_one_scan(
    config: dict[str, Any], outcome: tuple[Any, float] | Exception, code_path: str, base_metadata: dict[str, Any]
) -> dict[str, Any] | None:
    """Parse and enrich one scan's output; None if the scan failed (the error is logged)."""
    scan_type = config["scan_type"]
    if isinstance(outcome, Exception):
        error(f"{scan_type} scan failed: {outcome}")
        return None
    tool_output, duration = outcome
    try:
        metadata = {**base_metadata, 'scan_type': scan_type, 'scan_duration': duration}
        return build_results(scan_type, tool_output, config["tool_parser"], metadata, code_path)
    except Exception as e:
        error(f"{scan_type} scan failed: {e}")
        return None

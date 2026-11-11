import time
from collections.abc import Callable
from functools import cache
from importlib.metadata import entry_points
from typing import Any

import typer

from gerion_cli.core import (
    CLIENT_ID,
    LogLevel,
    OutputFormat,
    SecretString,
    debug,
    error,
    get_metadata,
    info,
    panel,
    set_log_level,
    warning,
)
from gerion_cli.output import findings_table, resolve_file_format, save_to_file
from gerion_cli.tools import ToolError


@cache
def _discover_enrichers():
    """
    Discover and instantiate premium enrichers via entry_points.

    Cached: scan-all enriches four scans, and the entry_points lookup scans every
    installed distribution.
    """
    eps = entry_points(group="gerion.enrichers")
    enrichers = []
    for ep in eps:
        try:
            cls = ep.load()
            enrichers.append(cls())
        except Exception as e:
            warning(f"Failed to load enricher '{ep.name}': {e}")
    return enrichers


def execute_tool(
    tool_name: str,
    tool_runner: Callable[..., Any],
    code_path: str,
    timeout: int,
    **runner_kwargs: Any,
) -> tuple[Any, float]:
    """
    Run one scanner and return (raw output, duration in seconds).

    Raises:
        ToolError: the scanner could not run or failed; there is no trustworthy result.
    """
    info(f"Running {tool_name} scan...")
    start_time = time.time()
    try:
        tool_output = tool_runner(code_path, timeout=timeout, **runner_kwargs)
    except ToolError:
        raise
    except Exception as e:
        raise ToolError(f"unexpected error running {tool_name}: {e}") from e
    scan_duration = round(time.time() - start_time, 2)
    # Scanners may run concurrently (scan-all): name the tool in the result line.
    info(f"{tool_name} found {len(tool_output)} potential issues in {scan_duration}s")
    return tool_output, scan_duration


def build_results(
    scan_type: str,
    tool_output: Any,
    tool_parser: Callable[[Any, dict[str, Any]], list[dict[str, Any]]],
    metadata: dict[str, Any],
    code_path: str,
) -> dict[str, Any]:
    """Parse and enrich a scanner's raw output into {'metadata', 'findings'}."""
    findings = tool_parser(tool_output, metadata)

    # Premium enrichment hook (entry_points)
    enrichers = _discover_enrichers()
    if enrichers:
        info(f"Enriching findings with {len(enrichers)} plugins...")
        for enricher in enrichers:
            try:
                findings = enricher.enrich(
                    findings,
                    code_path,
                    scan_type,
                    raw_output=tool_output
                )
            except Exception as e:
                warning(f"Enricher failed: {e}")

    results = {'metadata': metadata, 'findings': findings}

    panel(
        f"{scan_type} Scan Summary",
        f"Repository: {metadata['repository_name']}\n"
        f"Branch: {metadata['branch_name']}\n"
        f"Commit: {metadata['commit_hash'][:8] if metadata['commit_hash'] else 'N/A'}\n"
        f"Findings: {len(results['findings'])}\n"
        f"Duration: {metadata['scan_duration']}s",
        "blue"
    )
    return results


def write_output_file(results: dict[str, Any], output_file: str, format: OutputFormat | None) -> None:
    """Save results to --output-file; exit 1 with a clear error if it cannot be written."""
    try:
        save_to_file(results, output_file, resolve_file_format(output_file, format))
    except OSError as e:
        error(f"Could not write output file '{output_file}': {e.strerror or e}")
        raise typer.Exit(1) from None


def dispatch_results(
    results: dict[str, Any],
    scan_type: str,
    api_url: str | None,
    client_id: str | None,
    api_key: SecretString,
    output_file: str | None,
    format: OutputFormat | None,
) -> bool:
    """
    Returns True when the results were uploaded to the API but the upload failed
    (callers must then exit non-zero); False otherwise, including console mode.

    Output Priority:
    1. Output File -> Save to file (no table, no API)
    2. Format (explicitly requested) -> Print formatted output (no table, no API)
    3. API -> Send to API (fallback to table if failed)
    4. Fallback -> Print table (console mode)
    """
    if output_file:
        write_output_file(results, output_file, format)
        debug("Results saved to file. Console output and API sending suppressed.")

    elif format:
        # If format is provided and output_file is NOT set, print to stdout.
        if format == OutputFormat.TABLE:
            findings_table(results['findings'], scan_type)
            return False

        try:
            from gerion_cli.output import print_formatted
            print_formatted(results, format)
            debug(f"Results printed to console in {format} format.")
        except Exception as e:
            error(f"Error printing results: {e}")
            findings_table(results['findings'], scan_type)

    elif all([api_url, client_id, api_key]):
        # Imported here so commands that never talk to the API do not load httpx.
        from gerion_cli.api import send_to_api

        success_result = send_to_api(results, api_url, client_id, api_key)
        if not success_result:
            warning("Results will be displayed in console only.")
            findings_table(results['findings'], scan_type)
            return True
    else:
        # Fallback: Local console mode.
        if not api_key:
            warning("No API key provided. Results will not be sent to the API.")
        findings_table(results['findings'], scan_type)
    return False


def run_scan(
    scan_type: str,
    tool_name: str,
    tool_runner: Callable[..., Any],
    tool_parser: Callable[[Any, dict[str, Any]], list[dict[str, Any]]],
    code_path: str,
    api_url: str | None,
    client_id: str | None,
    api_key: str | None,
    output_file: str | None,
    format: OutputFormat,
    timeout: int,
    log_level: LogLevel,
    **runner_kwargs: Any
):
    """
    Base function to run a security scan using a specified tool runner and parser.

    Exits with code 1 when the scanner could not run or failed (a scan that did not
    happen must never be reported as "no findings") or when the API upload failed
    (CI must not believe the results were stored).
    """
    set_log_level(log_level)
    api_key_string = SecretString.from_typer_option(api_key)
    # Use default client_id if not provided
    effective_client_id = client_id or CLIENT_ID

    info(f"Starting {scan_type} scan...")
    debug(f"Scanning code path: {code_path}")

    metadata = get_metadata(code_path=code_path)
    metadata['scan_type'] = scan_type
    debug("Metadata collected successfully")

    try:
        tool_output, metadata['scan_duration'] = execute_tool(
            tool_name, tool_runner, code_path, timeout, **runner_kwargs
        )
    except ToolError as e:
        error(f"{scan_type} scan failed: {e}")
        raise typer.Exit(1) from None

    results = build_results(scan_type, tool_output, tool_parser, metadata, code_path)
    if dispatch_results(results, scan_type, api_url, effective_client_id, api_key_string, output_file, format):
        error(f"{scan_type} results could not be uploaded to the API; the findings above were not stored.")
        raise typer.Exit(1)
    return results

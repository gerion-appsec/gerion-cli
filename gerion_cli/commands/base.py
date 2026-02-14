import time
import typer
from typing import Callable, Any, Dict, List, Optional
from gerion_cli.core import (
    get_metadata,
    LogLevel,
    OutputFormat,
    set_log_level,
    info,
    warning,
    error,
    panel,
    debug,
    SecretString,
    CLIENT_ID
)
from gerion_cli.api import send_to_api
from gerion_cli.output import save_to_file, findings_table

def run_scan(
    scan_type: str,
    tool_name: str,
    tool_runner: Callable[..., Any],
    tool_parser: Callable[[Any, Dict[str, Any]], List[Dict[str, Any]]],
    code_path: str,
    api_url: Optional[str],
    client_id: Optional[str],
    api_key: Optional[str],
    output_file: Optional[str],
    format: OutputFormat,
    timeout: int,
    log_level: LogLevel,
    **runner_kwargs: Any
):
    """
    Base function to run a security scan using a specified tool runner and parser.
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
    
    info(f"Running {tool_name} scan...")

    # Run the tool with provided arguments
    start_time = time.time()
    try:
        tool_output = tool_runner(code_path, timeout=timeout, **runner_kwargs)
    except Exception as e:
        error(f"Error running {scan_type} tool: {e}")
        raise typer.Exit(1)
    finally:
        scan_duration = round(time.time() - start_time, 2)
        metadata['scan_duration'] = scan_duration

    if tool_output is None:
        error(f"Failed to run {scan_type} scan (tool returned None)")
        raise typer.Exit(1)

    info(f"Found {len(tool_output)} potential issues in {scan_duration}s")
    
    # Parse findings
    findings = tool_parser(tool_output, metadata)
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
    
    # Output Priority:
    # 1. Output File -> Save to file (no table, no API)
    # 2. Format (explicitly requested) -> Print formatted output (no table, no API)
    # 3. API -> Send to API (fallback to table if failed)
    # 4. Fallback -> Print table (console mode)

    if output_file:
        save_format = format
        if not save_format:
            lower_name = output_file.lower()
            if lower_name.endswith('.json'):
                save_format = OutputFormat.JSON
            elif lower_name.endswith('.md') or lower_name.endswith('.markdown'):
                save_format = OutputFormat.MARKDOWN
            elif lower_name.endswith('.sarif'):
                save_format = OutputFormat.SARIF
            else:
                warning(f"Could not infer format from file '{output_file}'. Defaulting to JSON.")
                save_format = OutputFormat.JSON

        save_to_file(results, output_file, save_format)
        debug("Results saved to file. Console output and API sending suppressed.")
    
    elif format:
        # If format is provided and output_file is NOT set, print to stdout.
        if format == OutputFormat.TABLE:
            findings_table(results['findings'], scan_type)
            return results

        try:
            from gerion_cli.output import print_formatted
            print_formatted(results, format)
            debug(f"Results printed to console in {format} format.")
        except Exception as e:
            error(f"Error printing results: {e}")
            findings_table(results['findings'], scan_type)

    elif all([api_url, effective_client_id, api_key_string]):
        success_result = send_to_api(results, api_url, effective_client_id, api_key_string)
        if not success_result:
            warning("Results will be displayed in console only.")
            findings_table(results['findings'], scan_type)
    else:
        # Fallback: Local console mode.
        if not api_key_string:
            warning("No API key provided. Results will not be sent to the API.")
        findings_table(results['findings'], scan_type)

    return results

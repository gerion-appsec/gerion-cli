import typer
from gerion_cli.core import LogLevel, OutputFormat, CLIENT_ID, info, panel
from gerion_cli.output import save_to_file, print_formatted, findings_table
from gerion_cli.tools import (
    run_secrets_tool, parse_secrets_tool_output,
    run_sca_tool, parse_sca_tool_output,
    run_iac_tool, parse_iac_tool_output,
    run_sast_tool, parse_sast_tool_output
)
from gerion_cli.commands.base import run_scan

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
    log_level: LogLevel = typer.Option(LogLevel.INFO, "--log-level", "-l", help="Set the logging level")
):
    """
    Run all security scans (Secrets, SCA, IaC, SAST) sequentially.

    This command runs Gitleaks, OSV-Scanner, KICS, and Opengrep in sequence.
    When --output-file is provided, all findings are aggregated into a single file.
    When sending to API, each scan submits independently.

    Examples:
        # Scan current directory with all tools
        gerion scan-all

        # Scan specific directory
        gerion scan-all /path/to/code

        # Save all results to a single file
        gerion scan-all --output-file results.json

        # Send to API Gateway
        gerion scan-all --api-url https://api.gerion.com --api-key YOUR_KEY
    """
    all_findings = []
    total_duration = 0.0
    last_metadata = None

    # When output_file or format is set, suppress file/format/API in individual
    # scans — scan_all handles aggregation and output at the end.
    suppress_output = output_file or format

    for config in SCAN_CONFIGS:
        results = run_scan(
            **config,
            code_path=code_path,
            api_url=None if suppress_output else api_url,
            client_id=None if suppress_output else client_id,
            api_key=None if suppress_output else api_key,
            output_file=None,
            format=None,
            timeout=timeout,
            log_level=log_level
        )
        if results:
            all_findings.extend(results['findings'])
            total_duration += results['metadata'].get('scan_duration', 0)
            last_metadata = results['metadata']

    # Aggregated output routing (mirrors base.py priority for individual scans)
    if last_metadata:
        aggregated = {
            'metadata': {
                **last_metadata,
                'scan_type': 'All',
                'scan_duration': round(total_duration, 2)
            },
            'findings': all_findings
        }

        if output_file:
            save_to_file(aggregated, output_file, format or OutputFormat.JSON)
            info(f"Aggregated results saved to {output_file}")
        elif format:
            if format == OutputFormat.TABLE:
                findings_table(all_findings, "All")
            else:
                print_formatted(aggregated, format)

    panel(
        "Full Scan Summary",
        f"Total findings: {len(all_findings)}\n"
        f"Total duration: {round(total_duration, 2)}s",
        "green"
    )

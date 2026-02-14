import typer
from gerion_cli.core import LogLevel, OutputFormat, CLIENT_ID
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
    output_file: str = typer.Option(None, "--output-file", "-o", help="Save results to a file (disables API sending)"),
    format: OutputFormat = typer.Option(OutputFormat.JSON, "--format", "-f", help="Output format for file saving"),
    timeout: int = typer.Option(180, "--timeout", "-t", help="Tool execution timeout in seconds (per scan)"),
    log_level: LogLevel = typer.Option(LogLevel.INFO, "--log-level", "-l", help="Set the logging level")
):
    """
    Run all security scans (Secrets, SCA, IaC, SAST) sequentially.

    This command runs Gitleaks, OSV-Scanner, KICS, and Opengrep in sequence.
    Each scan sends its results independently to the API or appends to the output file.

    Examples:
        # Scan current directory with all tools
        gerion-cli scan-all

        # Scan specific directory
        gerion-cli scan-all /path/to/code

        # Save all results to file
        gerion-cli scan-all --output-file results.json

        # Send to API Gateway
        gerion-cli scan-all --api-url https://api.gerion.com --api-key YOUR_KEY
    """
    for config in SCAN_CONFIGS:
        run_scan(
            **config,
            code_path=code_path,
            api_url=api_url,
            client_id=client_id,
            api_key=api_key,
            output_file=output_file,
            format=format,
            timeout=timeout,
            log_level=log_level
        )

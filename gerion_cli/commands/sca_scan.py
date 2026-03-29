import typer
from gerion_cli.core import LogLevel, OutputFormat, CLIENT_ID
from gerion_cli.tools import run_sca_tool, parse_sca_tool_output
from gerion_cli.commands.base import run_scan

def sca_scan(
    code_path: str = typer.Argument(".", help="Path to the code directory to scan", show_default=True),
    api_url: str = typer.Option(None, "--api-url", "-a", envvar="GERION_API_URL", help="API Gateway URL for sending results"),
    client_id: str = typer.Option(None, "--client-id", "-i", envvar="GERION_CLIENT_ID", help=f"Client ID for API authentication (default: {CLIENT_ID})"),
    api_key: str = typer.Option(None, "--api-key", "-k", envvar="GERION_API_KEY", hide_input=True, help="M2M API key for authentication"),
    output_file: str = typer.Option(None, "--output-file", "-o", help="Save results to a file (disables API sending)"),
    format: OutputFormat = typer.Option(None, "--format", "-f", help="Output format for file saving or stdout (json, markdown, sarif)"),
    timeout: int = typer.Option(180, "--timeout", "-t", help="Tool execution timeout in seconds"),
    log_level: LogLevel = typer.Option(LogLevel.INFO, "--log-level", "-l", help="Set the logging level")
):
    """
    Scan project dependencies for known vulnerabilities using OSV-Scanner.
    
    This command analyzes package dependencies (npm, pip, maven, etc.) and identifies
    known CVEs (Common Vulnerabilities and Exposures) in the installed packages using
    OSV-Scanner.
    Results can be sent to the API Gateway or saved to a local file.
    
    Examples:
        # Scan current directory
        gerion sca-scan
        
        # Scan specific directory
        gerion sca-scan /path/to/code
        
        # Save results to file
        gerion sca-scan --output-file results.json
        
        # Send to API Gateway
        gerion sca-scan --api-url https://api.gerion.dev --api-key YOUR_KEY
    """
    run_scan(
        scan_type="SCA",
        tool_name="OSV-Scanner",
        tool_runner=run_sca_tool,
        tool_parser=parse_sca_tool_output,
        code_path=code_path,
        api_url=api_url,
        client_id=client_id,
        api_key=api_key,
        output_file=output_file,
        format=format,
        timeout=timeout,
        log_level=log_level
    )

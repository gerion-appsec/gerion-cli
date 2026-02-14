import typer
from gerion_cli.core import LogLevel, OutputFormat, CLIENT_ID
from gerion_cli.tools import run_iac_tool, parse_iac_tool_output
from gerion_cli.commands.base import run_scan

def iac_scan(
    code_path: str = typer.Argument(".", help="Path to the code directory to scan", show_default=True),
    api_url: str = typer.Option(None, "--api-url", "-a", envvar="GERION_API_URL", help="API Gateway URL for sending results"),
    client_id: str = typer.Option(None, "--client-id", "-i", envvar="GERION_CLIENT_ID", help=f"Client ID for API authentication (default: {CLIENT_ID})"),
    api_key: str = typer.Option(None, "--api-key", "-k", envvar="GERION_API_KEY", hide_input=True, help="M2M API key for authentication"),
    output_file: str = typer.Option(None, "--output-file", "-o", help="Save results to a file (disables API sending)"),
    format: OutputFormat = typer.Option(None, "--format", "-f", help="Output format for file saving or stdout (json, markdown, sarif)"),
    timeout: int = typer.Option(180, "--timeout", "-t", help="Tool execution timeout in seconds"),
    queries_path: str = typer.Option(None, "--queries-path", "-q", help="Path to KICS queries directory (for non-standard installations)"),
    log_level: LogLevel = typer.Option(LogLevel.INFO, "--log-level", "-l", help="Set the logging level")
):
    """
    Scan Infrastructure as Code (IaC) files for security misconfigurations using KICS.
    
    This command analyzes Terraform, Kubernetes, Docker, and other IaC files to detect
    security misconfigurations and compliance issues using KICS.
    Results can be sent to the API Gateway or saved to a local file.
    
    Examples:
        # Scan current directory
        gerion-cli iac-scan
        
        # Scan specific directory
        gerion-cli iac-scan /path/to/terraform
        
        # Scan with custom queries path
        gerion-cli iac-scan --queries-path /path/to/kics/queries
        
        # Save results to file
        gerion-cli iac-scan --output-file results.json
        
        # Send to API Gateway
        gerion-cli iac-scan --api-url https://api.gerion.com --api-key YOUR_KEY
    """
    run_scan(
        scan_type="IaC",
        tool_name="KICS",
        tool_runner=run_iac_tool,
        tool_parser=parse_iac_tool_output,
        code_path=code_path,
        api_url=api_url,
        client_id=client_id,
        api_key=api_key,
        output_file=output_file,
        format=format,
        timeout=timeout,
        log_level=log_level,
        queries_path=queries_path
    )

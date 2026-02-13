import typer
from gerion_cli.core import (
    get_metadata, 
    LogLevel, 
    OutputFormat, 
    set_log_level, 
    info, 
    warning, 
    error, 
    success, 
    panel, 
    debug, 
    SecretString, 
    CLIENT_ID
)
from gerion_cli.tools import run_iac_tool, parse_iac_tool_output
from gerion_cli.api import send_to_api
from gerion_cli.output import save_to_file, findings_table

def iac_scan(
    code_path: str = typer.Argument(".", help="Path to the code directory to scan", show_default=True),
    api_url: str = typer.Option(None, "--api-url", "-a", envvar="GERION_API_URL", help="API Gateway URL for sending results"),
    client_id: str = typer.Option(None, "--client-id", "-i", envvar="GERION_CLIENT_ID", help=f"Client ID for API authentication (default: {CLIENT_ID})"),
    api_key: str = typer.Option(None, "--api-key", "-k", envvar="GERION_API_KEY", hide_input=True, help="M2M API key for authentication"),
    output_file: str = typer.Option(None, "--output-file", "-o", help="Save results to a file (disables API sending)"),
    format: OutputFormat = typer.Option(OutputFormat.JSON, "--format", "-f", help="Output format for file saving"),
    timeout: int = typer.Option(180, "--timeout", "-t", help="Tool execution timeout in seconds"),
    log_level: LogLevel = typer.Option(LogLevel.INFO, "--log-level", "-l", help="Set the logging level")
):
    """
    Scan Infrastructure as Code (IaC) files for security misconfigurations using Trivy.
    
    This command analyzes Terraform, Kubernetes, Docker, and other IaC files to detect
    security misconfigurations and compliance issues. Results can be sent to the
    API Gateway or saved to a local file.
    
    Examples:
        # Scan current directory
        gerion-cli iac-scan
        
        # Scan specific directory
        gerion-cli iac-scan /path/to/terraform
        
        # Save results to file
        gerion-cli iac-scan --output-file results.json
        
        # Send to API Gateway
        gerion-cli iac-scan --api-url https://api.gerion.com --api-key YOUR_KEY
    """
    set_log_level(log_level)
    api_key_string = SecretString.from_typer_option(api_key)
    # Use default client_id if not provided
    effective_client_id = client_id or CLIENT_ID
    info("Starting IaC scan...")
    debug(f"Scanning code path: {code_path}")
    metadata = get_metadata(code_path=code_path)
    metadata['scan_type'] = 'IaC'
    debug("Metadata collected successfully")
    info("Running Trivy IaC scan...")
    iac_tool_output = run_iac_tool(code_path, timeout=timeout)
    if iac_tool_output is None:
        error("Failed to run IaC scan")
        raise typer.Exit(1)
    info(f"Found {len(iac_tool_output)} potential misconfigurations")
    results = {'metadata':metadata, 'findings': parse_iac_tool_output(iac_tool_output, metadata)}
    panel(
        "IaC Scan Summary",
        f"Repository: {metadata['repository_name']}\n"
        f"Branch: {metadata['branch_name']}\n"
        f"Commit: {metadata['commit_hash'][:8] if metadata['commit_hash'] else 'N/A'}\n"
        f"Findings: {len(results['findings'])}",
        "blue"
    )
    if output_file:
        save_to_file(results, output_file, format)
        debug("Results saved to file. API sending disabled when output file is specified.")
    else:
        if not all([api_url, effective_client_id, api_key_string]):
            warning("No API credentials provided. Results will be displayed in console only.")
            findings_table(results['findings'], "IaC")
        else:
            success_result = send_to_api(results, api_url, effective_client_id, api_key_string)
            if not success_result:
                warning("Results will be displayed in console only.")
                findings_table(results['findings'], "IaC") 
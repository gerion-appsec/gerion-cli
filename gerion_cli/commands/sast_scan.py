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
from gerion_cli.tools import run_sast_tool, parse_sast_tool_output
from gerion_cli.api import send_to_api
from gerion_cli.output import save_to_file, findings_table



def sast_scan(
    code_path: str = typer.Argument(".", help="Path to the code directory to scan", show_default=True),
    api_url: str = typer.Option(None, "--api-url", "-a", envvar="GERION_API_URL", help="API Gateway URL for sending results"),
    client_id: str = typer.Option(None, "--client-id", "-i", envvar="GERION_CLIENT_ID", help=f"Client ID for API authentication (default: {CLIENT_ID})"),
    api_key: str = typer.Option(None, "--api-key", "-k", envvar="GERION_API_KEY", hide_input=True, help="M2M API key for authentication"),
    output_file: str = typer.Option(None, "--output-file", "-o", help="Save results to a file (disables API sending)"),
    format: OutputFormat = typer.Option(OutputFormat.JSON, "--format", "-f", help="Output format for file saving"),
    log_level: LogLevel = typer.Option(LogLevel.INFO, "--log-level", "-l", help="Set the logging level")
):
    """
    Scan codebase for security vulnerabilities using Semgrep (SAST).
    
    This command performs a Static Application Security Testing (SAST) using Semgrep to identify
    potential vulnerabilities in the code. If Premium is active, it also performs 
    Deep Reachability Analysis using Atom.
    """
    set_log_level(log_level)
    api_key_string = SecretString.from_typer_option(api_key)
    # Use default client_id if not provided
    effective_client_id = client_id or CLIENT_ID
    info("Starting SAST scan...")
    debug(f"Scanning code path: {code_path}")
    metadata = get_metadata(code_path=code_path)
    metadata['scan_type'] = 'SAST'
    debug("Metadata collected successfully")
    info("Running Semgrep scan...")
    
    # Run Tool
    sast_results = run_sast_tool(code_path)
    
    if sast_results is None:
        error("Failed to run SAST scan")
        raise typer.Exit(1)
        
    info(f"Found {len(sast_results)} potential vulnerabilities")
    
    # Parse and Enrich
    parsed_findings = parse_sast_tool_output(sast_results, metadata)
    
    results = {'metadata':metadata, 'findings': parsed_findings}
    
    panel(
        "SAST Scan Summary",
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
            findings_table(results['findings'], "SAST")
        else:
            success_result = send_to_api(results, api_url, effective_client_id, api_key_string)
            if not success_result:
                warning("Results will be displayed in console only.")
                findings_table(results['findings'], "SAST")

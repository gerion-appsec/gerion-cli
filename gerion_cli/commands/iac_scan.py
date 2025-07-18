import typer
from typing_extensions import Annotated
from gerion_cli.core.metadata import get_metadata
from gerion_cli.tools.iac import run_iac_tool
from gerion_cli.tools.parser import parse_iac_tool_output
from gerion_cli.api.client import send_to_api
from gerion_cli.output.formats import save_to_file
from gerion_cli.core.logging import LogLevel, OutputFormat, set_log_level, info, warning, error, success, panel, debug
from gerion_cli.output.tables import findings_table
from gerion_cli.core.types import SecretString

app = typer.Typer()

@app.command()
def iac_scan(
    code_path: Annotated[str, typer.Argument()] = ".",
    api_url: str = typer.Option(None, envvar="GERION_API_URL", help="API URL for sending results"),
    client_id: str = typer.Option(None, envvar="GERION_CLIENT_ID", help="Client ID for API authentication"),
    client_secret: str = typer.Option(None, envvar="GERION_CLIENT_SECRET", hide_input=True, help="Client secret for API authentication"),
    output_file: str = typer.Option(None, help="Save results to a file (disables API sending)"),
    format: OutputFormat = typer.Option(OutputFormat.JSON, help="Output format for file saving"),
    log_level: LogLevel = typer.Option(LogLevel.INFO, help="Set the logging level")
):
    set_log_level(log_level)
    secret_string = SecretString.from_typer_option(client_secret)
    info("Starting IaC scan...")
    debug(f"Scanning code path: {code_path}")
    metadata = get_metadata()
    debug("Metadata collected successfully")
    info("Running Trivy IaC scan...")
    iac_tool_output = run_iac_tool(code_path)
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
        if not all([api_url, client_id, secret_string]):
            warning("No API credentials provided. Results will be displayed in console only.")
            findings_table(results['findings'], "IaC")
        else:
            success = send_to_api(results, api_url, client_id, secret_string)
            if not success:
                warning("Results will be displayed in console only.")
                findings_table(results['findings'], "IaC") 
import typer
from typing_extensions import Annotated
from gerion_cli.utils.metadata_utils import get_metadata
from gerion_cli.utils.sca_tool_utils import run_sca_tool
from gerion_cli.utils.parsing_utils import parse_sca_tool_output
from gerion_cli.utils.aux_utils import send_to_api, save_to_json

app = typer.Typer()

@app.command()
def sca_scan(
    code_path: Annotated[str, typer.Argument()] = ".",
    api_url: str = typer.Option(None, help="API URL for sending results"),
    api_token: str = typer.Option(None, help="API token for authentication"),
    output_file: str = typer.Option(None, help="Save results to a JSON file")
):
    metadata = get_metadata()
    sca_tool_output = run_sca_tool(code_path)
    results = {'metadata':metadata, 'findings': parse_sca_tool_output(sca_tool_output, metadata)}

    if api_url and api_token:
        send_to_api(results, api_url, api_token)
    
    if output_file:
        save_to_json(results, output_file)
    
    if not (api_url or api_token or output_file):
        typer.echo(results)
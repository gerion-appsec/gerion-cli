import typer
from typing_extensions import Annotated
import json
from gerion_cli.utils.metadata_utils import get_metadata
from gerion_cli.utils.secrets_tool_utils import run_secrets_tool
from gerion_cli.utils.parsing_utils import parse_secrets_tool_output

app = typer.Typer()

# Aux functions
def save_to_json(results, filename: str):
    with open(filename, 'w') as json_file:
        json.dump(results, json_file, indent=4)
    typer.echo(f"Results saved to {filename}")

def send_to_api(results, api_url: str, api_token: str):
    import httpx
    
    api_url = f'{api_url}/api/client/findings'
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json"
    }

    response = httpx.post(api_url, headers=headers, json=json.dumps(results))
    
    if response.status_code >= 200 and response.status_code < 300:
        typer.echo("Data sent to API successfully.")
    else:
        typer.echo(f"Failed to send data to API: {response.status_code} - {response.text}")

@app.command()
def secrets_scan(
    code_path: Annotated[str, typer.Argument()] = ".",
    api_url: str = typer.Option(None, help="API URL for sending results"),
    api_token: str = typer.Option(None, help="API token for authentication"),
    output_file: str = typer.Option(None, help="Save results to a JSON file")
):
    metadata = get_metadata()
    secrets_tool_output = run_secrets_tool(code_path)
    results = {'metadata':metadata, 'findings': parse_secrets_tool_output(secrets_tool_output, metadata)}

    if api_url and api_token:
        send_to_api(results, api_url, api_token)
    
    if output_file:
        save_to_json(results, output_file)
    
    if not (api_url or api_token or output_file):
        typer.echo(results)
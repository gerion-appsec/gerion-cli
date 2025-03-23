import typer
from gerion_cli.utils.metadata_utils import get_metadata
from gerion_cli.utils.secrets_tool_utils import run_secrets_tool
from gerion_cli.utils.parsing_utils import parse_secrets_tool_output

app = typer.Typer()

@app.command()
def secrets_scan(api_url: str, api_token: str):
    metadata = get_metadata()
    # print(f'metadata: {metadata}')
    secrets_tool_output = run_secrets_tool('.')
    # print(f'secrets_tool_output: {secrets_tool_output}')
    results = parse_secrets_tool_output(secrets_tool_output)
    # print(f'results: {results}')
    typer.echo(results)
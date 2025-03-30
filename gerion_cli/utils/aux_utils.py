import typer
import json

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

    try:
        response = httpx.post(api_url, headers=headers, json=json.dumps(results))

        if response.status_code >= 200 and response.status_code < 300:
            typer.echo("Data sent to API successfully.")
        else:
            typer.echo(f"Error sending data to API: {response.status_code}")

    except httpx.HTTPError as e:
        typer.echo(f"HTTP Error: {e}")

    except Exception as e:
        typer.echo(f"Unexpected Error: {e}")
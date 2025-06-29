"""
HTTP client functionality for Gerion API.
"""
import httpx
from gerion_cli.core.types import SecretString
from gerion_cli.core.logging import debug, error, success
from gerion_cli.api.auth import authenticate_with_api

def send_to_api(results, api_url: str, client_id: str, client_secret: SecretString):
    """
    Send results to the API with JWT authentication.
    """
    # Check if we have all required credentials
    if not all([api_url, client_id, client_secret]):
        error("Missing API credentials. Please provide them via parameters or environment variables:")
        error("  - GERION_API_URL or --api-url")
        error("  - GERION_CLIENT_ID or --client-id")
        error("  - GERION_CLIENT_SECRET or --client-secret")
        return False
    
    debug("Starting API authentication...")
    
    # First authenticate to get JWT token
    token = authenticate_with_api(api_url, client_id, client_secret)
    
    if not token:
        error("Failed to authenticate with API. Cannot send results.")
        return False
    
    # Prepare the data according to the API schema
    api_data = {
        "findings_data": {
            "metadata": results['metadata'],
            "findings": results['findings']
        }
    }
    
    # Send findings to API
    findings_url = f'{api_url}/api/v1/findings'
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    try:
        debug("Sending findings to API...")
        response = httpx.post(findings_url, headers=headers, json=api_data)

        if response.status_code >= 200 and response.status_code < 300:
            success("Data sent to API successfully.")
            return True
        else:
            error(f"Error sending data to API: {response.status_code} - {response.text}")
            return False

    except httpx.HTTPError as e:
        error(f"HTTP Error: {e}")
        return False
    except Exception as e:
        error(f"Unexpected Error: {e}")
        return False 
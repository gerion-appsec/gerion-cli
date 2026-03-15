"""
HTTP client functionality for Gerion API.
"""
import httpx
from gerion_cli.core.types import SecretString
from gerion_cli.core.logging import debug, error, success
from gerion_cli.api.auth import authenticate_with_api

def send_to_api(results, api_url: str, client_id: str, api_key: SecretString):
    """
    Send results to the API Gateway with JWT authentication.
    
    Uses M2M API key authentication to get a JWT token, then sends findings
    to the API Gateway findings endpoint.
    """
    # Check if we have all required credentials
    if not all([api_url, client_id, api_key]):
        error("Missing API credentials. Please provide them via parameters or environment variables:")
        error("  - GERION_API_URL or --api-url")
        error("  - GERION_CLIENT_ID or --client-id")
        error("  - GERION_API_KEY or --api-key")
        return False
    
    debug("Starting M2M API authentication...")
    
    # First authenticate to get JWT token using M2M API key
    token = authenticate_with_api(api_url, client_id, api_key)
    
    if not token:
        error("Failed to authenticate with API Gateway. Cannot send results.")
        return False
    
    # Prepare the data according to the API Gateway schema
    # API Gateway accepts flexible format with findings_data or direct metadata/findings
    api_data = {
        "findings_data": {
            "scan_metadata": results['metadata'],
            "findings": results['findings']
        }
    }
    
    # Send findings to API Gateway
    findings_url = f'{api_url}/api/v1/findings'
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    try:
        debug("Sending findings to API Gateway...")
        response = httpx.post(findings_url, headers=headers, json=api_data)

        if response.status_code >= 200 and response.status_code < 300:
            success("Data sent to API Gateway successfully.")
            return True
        else:
            error(f"Error sending data to API Gateway: {response.status_code} - {response.text}")
            return False

    except httpx.HTTPError as e:
        error(f"HTTP Error: {e}")
        return False
    except Exception as e:
        error(f"Unexpected Error: {e}")
        return False 
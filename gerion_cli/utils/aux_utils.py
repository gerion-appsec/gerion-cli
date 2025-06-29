import typer
import json
import httpx
from .secret_types import SecretString
from .logging_utils import debug, info, warning, error, success, panel
from .output_formats import save_to_file

def authenticate_with_api(api_url: str, client_id: str, client_secret: SecretString):
    """
    Authenticate with the API and get JWT token.
    """
    auth_url = f'{api_url}/api/v1/team/token'
    auth_data = {
        "client_id": client_id,
        "client_secret": client_secret.get_secret_value()
    }
    
    try:
        debug(f"Authenticating with: {auth_url}")
        response = httpx.post(auth_url, json=auth_data, headers={"Content-Type": "application/json"})
        
        debug(f"Response status: {response.status_code}")
        
        if response.status_code == 200:
            try:
                token_data = response.json()
                debug(f"Response data: {json.dumps(token_data, indent=2)}")
                
                # Try different possible token field names
                token = None
                possible_token_fields = ['token', 'access_token', 'jwt_token', 'accessToken', 'jwtToken']
                
                for field in possible_token_fields:
                    if field in token_data and token_data[field]:
                        token = token_data[field]
                        debug(f"Found token in field: {field}")
                        break
                
                if token:
                    info("Authentication successful")
                    return token
                else:
                    error("No token found in response. Available fields:")
                    for key, value in token_data.items():
                        debug(f"  {key}: {type(value).__name__}")
                    return None
                    
            except json.JSONDecodeError as e:
                error(f"Failed to parse JSON response: {e}")
                debug(f"Raw response: {response.text}")
                return None
        else:
            error(f"Authentication failed: {response.status_code} - {response.text}")
            return None
            
    except httpx.HTTPError as e:
        error(f"HTTP Error during authentication: {e}")
        return None
    except Exception as e:
        error(f"Unexpected Error during authentication: {e}")
        return None

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
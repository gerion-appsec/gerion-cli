"""
Authentication functionality for Gerion API.
Uses M2M API key authentication to get JWT tokens from API Gateway.
"""
import json
import httpx
from gerion_cli.core.types import SecretString
from gerion_cli.core.logging import debug, info, error

def authenticate_with_api(api_url: str, client_id: str, api_key: SecretString):
    """
    Authenticate with the API Gateway using M2M API key and get JWT token.
    
    Uses the M2M authentication endpoint: POST /api/v1/auth/m2m/authenticate
    API key can be provided via Authorization Bearer header or X-API-Key header.
    """
    auth_url = f'{api_url}/api/v1/auth/m2m/authenticate'
    auth_data = {
        "client_id": client_id
    }
    
    # API key can be sent via Authorization Bearer header (recommended) or X-API-Key header
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key.get_secret_value()}"
    }
    
    try:
        debug(f"Authenticating with M2M API key at: {auth_url}")
        debug(f"Client ID: {client_id}")
        response = httpx.post(auth_url, json=auth_data, headers=headers, follow_redirects=True)
        
        debug(f"Response status: {response.status_code}")
        
        if response.status_code == 200:
            try:
                token_data = response.json()
                debug(f"Response data: {json.dumps(token_data, indent=2)}")
                
                # M2M endpoint returns access_token in the response
                access_token = token_data.get('access_token')
                
                if access_token:
                    info("M2M authentication successful")
                    debug(f"Token expires in: {token_data.get('expires_in', 'unknown')} seconds")
                    debug(f"API Key ID: {token_data.get('api_key_id', 'unknown')}")
                    return access_token
                else:
                    error("No access_token found in response. Available fields:")
                    for key, value in token_data.items():
                        debug(f"  {key}: {type(value).__name__}")
                    return None
                    
            except json.JSONDecodeError as e:
                error(f"Failed to parse JSON response: {e}")
                debug(f"Raw response: {response.text}")
                return None
        elif response.status_code == 401:
            error("Authentication failed: Invalid API key or client_id")
            debug(f"Response: {response.text}")
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
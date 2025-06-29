"""
Authentication functionality for Gerion API.
"""
import json
import httpx
from gerion_cli.core.types import SecretString
from gerion_cli.core.logging import debug, info, error

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
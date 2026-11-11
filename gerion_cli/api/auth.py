"""
Authentication functionality for Gerion API.
Uses M2M API key authentication to get JWT tokens from API Gateway.
"""
import json

import httpx

from gerion_cli.api.http import HTTP_TIMEOUT, ApiConfigError, check_api_url, response_excerpt, ssl_verify
from gerion_cli.core.logging import debug, error, info
from gerion_cli.core.types import SecretString


def authenticate_with_api(api_url: str, client_id: str, api_key: SecretString):
    """
    Authenticate with the API Gateway using M2M API key and get JWT token.
    
    Uses the M2M authentication endpoint: POST /api/v1/auth/m2m/authenticate
    API key can be provided via Authorization Bearer header or X-API-Key header.
    """
    try:
        api_url = check_api_url(api_url)
        ssl_context = ssl_verify()
    except ApiConfigError as e:
        error(str(e))
        return None

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
        response = httpx.post(
            auth_url, json=auth_data, headers=headers, follow_redirects=True, verify=ssl_context, timeout=HTTP_TIMEOUT
        )

        debug(f"Response status: {response.status_code}")

        if response.status_code == 200:
            try:
                token_data = response.json()
                # Never log values: the response carries the access token.
                debug(f"Response fields: {', '.join(sorted(token_data))}")

                # M2M endpoint returns access_token in the response
                access_token = token_data.get('access_token')

                if access_token:
                    info("M2M authentication successful")
                    debug(f"Token expires in: {token_data.get('expires_in', 'unknown')} seconds")
                    debug(f"API Key ID: {token_data.get('api_key_id', 'unknown')}")
                    return access_token
                else:
                    error("No access_token found in response.")
                    return None

            except json.JSONDecodeError as e:
                error(f"Failed to parse JSON response: {e}")
                debug(f"Response content type: {response.headers.get('content-type', 'unknown')}")
                return None
        elif response.status_code == 401:
            error("Authentication failed: Invalid API key or client_id")
            debug(f"Response: {response_excerpt(response)}")
            return None
        else:
            error(f"Authentication failed: {response.status_code} - {response_excerpt(response)}")
            return None

    except httpx.HTTPError as e:
        error(f"HTTP Error during authentication: {e}")
        return None
    except Exception as e:
        error(f"Unexpected Error during authentication: {e}")
        return None

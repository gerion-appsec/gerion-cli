"""
HTTP client functionality for Gerion API.
"""
import httpx

from gerion_cli.api.auth import authenticate_with_api
from gerion_cli.api.http import HTTP_TIMEOUT, check_api_url, response_excerpt, ssl_verify
from gerion_cli.core.logging import debug, error, success
from gerion_cli.core.types import SecretString

# JWTs obtained in this process, by (api_url, client_id): scan-all uploads four scans
# and should authenticate (and send the API key) once, not four times.
_token_cache: dict[tuple[str, str], str] = {}


def _get_token(api_url: str, client_id: str, api_key: SecretString) -> str | None:
    """A JWT for (api_url, client_id): the cached one, or a new one. Failures are not cached."""
    key = (api_url, client_id)
    token = _token_cache.get(key)
    if token:
        debug("Reusing the API token obtained earlier in this run.")
        return token
    token = authenticate_with_api(api_url, client_id, api_key)
    if token:
        _token_cache[key] = token
    return token


def _post_findings(findings_url: str, token: str, api_data: dict) -> httpx.Response:
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    return httpx.post(
        findings_url, headers=headers, json=api_data, follow_redirects=True, verify=ssl_verify(), timeout=HTTP_TIMEOUT
    )


def send_to_api(results, api_url: str, client_id: str, api_key: SecretString):
    """
    Send results to the API Gateway with JWT authentication.
    
    Uses M2M API key authentication to get a JWT token (reused for the rest of the
    run), then sends findings to the API Gateway findings endpoint.
    """
    # Check if we have all required credentials
    if not all([api_url, client_id, api_key]):
        error("Missing API credentials. Please provide them via parameters or environment variables:")
        error("  - GERION_API_URL or --api-url")
        error("  - GERION_CLIENT_ID or --client-id")
        error("  - GERION_API_KEY or --api-key")
        return False

    debug("Starting M2M API authentication...")

    # Authenticate to get a JWT token using the M2M API key (once per run)
    token = _get_token(api_url, client_id, api_key)

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

    # Send findings to API Gateway (URL and TLS settings were validated by authentication)
    findings_url = f'{check_api_url(api_url)}/api/v1/findings'

    try:
        debug("Sending findings to API Gateway...")
        response = _post_findings(findings_url, token, api_data)

        if response.status_code == 401:
            # The cached token may have expired or been revoked: authenticate again, once.
            debug("API token rejected; re-authenticating once.")
            _token_cache.pop((api_url, client_id), None)
            token = _get_token(api_url, client_id, api_key)
            if not token:
                error("Failed to authenticate with API Gateway. Cannot send results.")
                return False
            response = _post_findings(findings_url, token, api_data)

        if response.status_code >= 200 and response.status_code < 300:
            success("Data sent to API Gateway successfully.")
            return True
        else:
            error(f"Error sending data to API Gateway: {response.status_code} - {response_excerpt(response)}")
            return False

    except httpx.HTTPError as e:
        error(f"HTTP Error: {e}")
        return False
    except Exception as e:
        error(f"Unexpected Error: {e}")
        return False

"""
Shared HTTP transport settings for the Gerion API Gateway.
"""
import os
import ssl
from urllib.parse import urlsplit

import httpx

from gerion_cli.core.logging import warning

# Large findings uploads need more than httpx's 5 s default.
HTTP_TIMEOUT = httpx.Timeout(60.0, connect=10.0)

RESPONSE_EXCERPT_CHARS = 300
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
_warned_insecure_urls: set[str] = set()


class ApiConfigError(Exception):
    """The API URL or TLS settings are unusable."""


def ssl_verify() -> ssl.SSLContext | bool:
    """
    TLS verification for httpx: a context built from GERION_CA_BUNDLE (a CA file or a
    directory of hashed certificates), or True for httpx's default trust store.
    """
    bundle = os.environ.get("GERION_CA_BUNDLE")
    if not bundle:
        return True
    try:
        if os.path.isdir(bundle):
            return ssl.create_default_context(capath=bundle)
        if os.path.isfile(bundle):
            return ssl.create_default_context(cafile=bundle)
    except ssl.SSLError as e:
        raise ApiConfigError(f"GERION_CA_BUNDLE '{bundle}' is not a valid CA bundle: {e}") from e
    raise ApiConfigError(f"GERION_CA_BUNDLE '{bundle}' does not exist.")


def check_api_url(api_url: str) -> str:
    """
    Validate the API base URL and return it without a trailing slash.

    The API key is sent to this URL, so plain http:// to a non-local host is warned
    about (it is still allowed for local and container development).
    """
    parts = urlsplit(api_url or "")
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ApiConfigError(f"Invalid API URL '{api_url}': it must start with https:// (or http:// for local development).")
    if parts.scheme == "http" and parts.hostname not in _LOCAL_HOSTS and api_url not in _warned_insecure_urls:
        _warned_insecure_urls.add(api_url)
        warning(f"API URL '{api_url}' is not https: the API key and findings are sent unencrypted.")
    return api_url.rstrip("/")


def response_excerpt(response: httpx.Response) -> str:
    """A bounded excerpt of a response body for error messages (bodies can echo whole payloads)."""
    text = response.text or ""
    if len(text) > RESPONSE_EXCERPT_CHARS:
        return text[:RESPONSE_EXCERPT_CHARS] + "... (truncated)"
    return text

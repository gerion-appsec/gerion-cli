"""
Shared HTTP transport settings for the Gerion API Gateway.
"""
import httpx

RESPONSE_EXCERPT_CHARS = 300


def response_excerpt(response: httpx.Response) -> str:
    """A bounded excerpt of a response body for error messages (bodies can echo whole payloads)."""
    text = response.text or ""
    if len(text) > RESPONSE_EXCERPT_CHARS:
        return text[:RESPONSE_EXCERPT_CHARS] + "... (truncated)"
    return text

import pytest
from unittest.mock import patch, MagicMock
import httpx
from gerion_cli.api.auth import authenticate_with_api
from gerion_cli.core.types import SecretString

@pytest.fixture
def mock_api_key():
    return SecretString("test-api-key")

@patch("gerion_cli.api.auth.httpx.post")
def test_authenticate_success(mock_post, mock_api_key):
    """Test successful API authentication."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "access_token": "valid.jwt.token",
        "expires_in": 3600,
        "token_type": "bearer"
    }
    mock_post.return_value = mock_response
    
    token = authenticate_with_api("http://api.test", "client-id", mock_api_key)
    
    assert token == "valid.jwt.token"
    mock_post.assert_called_once()

@patch("gerion_cli.api.auth.httpx.post")
def test_authenticate_failure_401(mock_post, mock_api_key):
    """Test authentication failure (401)."""
    mock_response = MagicMock()
    mock_response.status_code = 401
    mock_response.text = "Unauthorized"
    mock_post.return_value = mock_response
    
    token = authenticate_with_api("http://api.test", "client-id", mock_api_key)
    
    assert token is None

@patch("gerion_cli.api.auth.httpx.post")
def test_authenticate_network_error(mock_post, mock_api_key):
    """Test handling of network exceptions."""
    mock_post.side_effect = httpx.ConnectError("Connection failed")
    
    token = authenticate_with_api("http://api.test", "client-id", mock_api_key)
    
    assert token is None

@patch("gerion_cli.api.auth.httpx.post")
def test_authenticate_invalid_json(mock_post, mock_api_key):
    """Test handling of invalid JSON response."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    # Mock json() to raise JSONDecodeError directly
    from json import JSONDecodeError
    mock_response.json.side_effect = JSONDecodeError("msg", "doc", 0)
    
    token = authenticate_with_api("http://api.test", "client-id", mock_api_key)
    
    assert token is None

import ssl
import warnings
from unittest.mock import MagicMock, patch

import certifi
import pytest

from gerion_cli.api import http
from gerion_cli.api.auth import authenticate_with_api
from gerion_cli.api.http import HTTP_TIMEOUT, ApiConfigError, check_api_url, ssl_verify
from gerion_cli.core.types import SecretString


def test_ssl_verify_defaults_to_httpx_trust_store(monkeypatch):
    monkeypatch.delenv("GERION_CA_BUNDLE", raising=False)
    assert ssl_verify() is True


def test_ssl_verify_builds_context_from_file_and_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("GERION_CA_BUNDLE", certifi.where())
    assert isinstance(ssl_verify(), ssl.SSLContext)
    monkeypatch.setenv("GERION_CA_BUNDLE", str(tmp_path))
    assert isinstance(ssl_verify(), ssl.SSLContext)


def test_ssl_verify_rejects_missing_or_invalid_bundle(monkeypatch, tmp_path):
    monkeypatch.setenv("GERION_CA_BUNDLE", str(tmp_path / "missing.pem"))
    with pytest.raises(ApiConfigError, match="does not exist"):
        ssl_verify()
    garbage = tmp_path / "garbage.pem"
    garbage.write_text("not a certificate")
    monkeypatch.setenv("GERION_CA_BUNDLE", str(garbage))
    with pytest.raises(ApiConfigError, match="not a valid CA bundle"):
        ssl_verify()


@pytest.mark.parametrize("url", ["ftp://api.example.com", "api.example.com", "file:///etc/passwd", "", "https://"])
def test_check_api_url_rejects_non_http_urls(url):
    with pytest.raises(ApiConfigError, match="Invalid API URL"):
        check_api_url(url)


def test_check_api_url_warns_only_for_remote_plain_http(monkeypatch):
    warned = []
    monkeypatch.setattr(http, "warning", warned.append)
    monkeypatch.setattr(http, "_warned_insecure_urls", set())

    assert check_api_url("https://api.example.com/") == "https://api.example.com"
    check_api_url("http://localhost:8000")
    check_api_url("http://127.0.0.1")
    check_api_url("http://[::1]:8080")
    assert warned == []

    check_api_url("http://gateway:8000")
    check_api_url("http://gateway:8000")
    assert len(warned) == 1
    assert "not https" in warned[0]


@patch("gerion_cli.api.auth.httpx.post")
def test_authenticate_uses_context_and_explicit_timeout(mock_post, monkeypatch):
    monkeypatch.setenv("GERION_CA_BUNDLE", certifi.where())
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = {"access_token": "t"}
    mock_post.return_value = mock_response

    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        assert authenticate_with_api("https://api.test/", "client", SecretString("k")) == "t"

    args, kwargs = mock_post.call_args
    assert args[0] == "https://api.test/api/v1/auth/m2m/authenticate"
    assert isinstance(kwargs["verify"], ssl.SSLContext)
    assert kwargs["timeout"] is HTTP_TIMEOUT


@patch("gerion_cli.api.auth.httpx.post")
def test_authenticate_bad_config_never_sends_the_key(mock_post, monkeypatch):
    monkeypatch.setenv("GERION_CA_BUNDLE", "/nonexistent/ca.pem")
    assert authenticate_with_api("https://api.test", "client", SecretString("k")) is None
    monkeypatch.delenv("GERION_CA_BUNDLE")
    assert authenticate_with_api("ftp://api.test", "client", SecretString("k")) is None
    mock_post.assert_not_called()

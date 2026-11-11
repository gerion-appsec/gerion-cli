from unittest.mock import MagicMock, patch

import pytest

from gerion_cli.api import client
from gerion_cli.api.client import send_to_api
from gerion_cli.core.types import SecretString

API_URL = "https://api.test"
RESULTS = {"metadata": {"scan_type": "SAST"}, "findings": []}


@pytest.fixture(autouse=True)
def _empty_token_cache(monkeypatch):
    monkeypatch.setattr(client, "_token_cache", {})


def _response(status_code, payload=None):
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = payload or {}
    response.text = ""
    return response


class FakeGateway:
    """Stands in for httpx.post: answers the auth and findings endpoints."""

    def __init__(self, auth_statuses=(200,), findings_statuses=(201,)):
        self.auth_statuses = list(auth_statuses)
        self.findings_statuses = list(findings_statuses)
        self.auth_calls = 0
        self.findings_tokens = []

    def __call__(self, url, **kwargs):
        if url.endswith("/api/v1/auth/m2m/authenticate"):
            self.auth_calls += 1
            status = self.auth_statuses.pop(0) if len(self.auth_statuses) > 1 else self.auth_statuses[0]
            return _response(status, {"access_token": f"jwt-{self.auth_calls}"} if status == 200 else None)
        self.findings_tokens.append(kwargs["headers"]["Authorization"])
        status = self.findings_statuses.pop(0) if len(self.findings_statuses) > 1 else self.findings_statuses[0]
        return _response(status)


def _send():
    return send_to_api(RESULTS, API_URL, "client-id", SecretString("key"))


def test_authenticates_once_for_several_uploads():
    gateway = FakeGateway()
    with patch("gerion_cli.api.auth.httpx.post", side_effect=gateway):
        assert all(_send() for _ in range(4))
    assert gateway.auth_calls == 1
    assert gateway.findings_tokens == ["Bearer jwt-1"] * 4


def test_token_is_cached_per_url_and_client():
    gateway = FakeGateway()
    with patch("gerion_cli.api.auth.httpx.post", side_effect=gateway):
        assert _send()
        assert send_to_api(RESULTS, API_URL, "other-client", SecretString("key"))
    assert gateway.auth_calls == 2


def test_rejected_token_is_renewed_once_and_upload_retried():
    gateway = FakeGateway(findings_statuses=(201, 401, 201))
    with patch("gerion_cli.api.auth.httpx.post", side_effect=gateway):
        assert _send()
        assert _send()
    assert gateway.auth_calls == 2
    assert gateway.findings_tokens == ["Bearer jwt-1", "Bearer jwt-1", "Bearer jwt-2"]
    assert client._token_cache[(API_URL, "client-id")] == "jwt-2"


def test_upload_is_retried_only_once():
    gateway = FakeGateway(findings_statuses=(401,))
    with patch("gerion_cli.api.auth.httpx.post", side_effect=gateway):
        assert _send() is False
    assert gateway.auth_calls == 2
    assert len(gateway.findings_tokens) == 2


def test_failed_authentication_is_not_cached():
    gateway = FakeGateway(auth_statuses=(401, 200))
    with patch("gerion_cli.api.auth.httpx.post", side_effect=gateway):
        assert _send() is False
        assert client._token_cache == {}
        assert _send()
    assert gateway.auth_calls == 2
    assert gateway.findings_tokens == ["Bearer jwt-2"]


def test_failed_reauthentication_reports_failure():
    gateway = FakeGateway(auth_statuses=(200, 401), findings_statuses=(401,))
    with patch("gerion_cli.api.auth.httpx.post", side_effect=gateway):
        assert _send() is False
    assert client._token_cache == {}
    assert len(gateway.findings_tokens) == 1


def test_debug_output_never_contains_the_token(capsys):
    from gerion_cli.core.logging import LogLevel, set_log_level

    gateway = FakeGateway(findings_statuses=(201, 401, 201))
    set_log_level(LogLevel.DEBUG)
    try:
        with patch("gerion_cli.api.auth.httpx.post", side_effect=gateway):
            assert _send()
            assert _send()
    finally:
        set_log_level(LogLevel.INFO)
    captured = capsys.readouterr()
    assert "jwt-" not in captured.out + captured.err

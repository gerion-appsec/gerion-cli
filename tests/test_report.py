import importlib
import json

import pytest

from gerion_cli.commands.report import REPORT_LIMIT, ReportFormat, generate_markdown_report

# gerion_cli.commands re-exports the report function under the module's name.
report_module = importlib.import_module("gerion_cli.commands.report")


class _FakeResponse:
    def __init__(self, data):
        self._data = data

    def raise_for_status(self):
        pass

    def json(self):
        return self._data


class _FakeClient:
    def __init__(self, data):
        self._data = data

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def get(self, url, params, headers):
        assert params["limit"] == REPORT_LIMIT
        return _FakeResponse(self._data)


def _run_report(monkeypatch, tmp_path, findings):
    warnings = []
    # report() imports these lazily, so patch them where they are defined.
    monkeypatch.setattr("gerion_cli.api.auth.authenticate_with_api", lambda *a: "jwt")
    monkeypatch.setattr("httpx.Client", lambda **kw: _FakeClient(findings))
    monkeypatch.setattr(report_module, "warning", warnings.append)
    output = tmp_path / "r.json"
    report_module.report(
        path=str(tmp_path), repo="r", branch="b", scan_type=None, severity=None, format=ReportFormat.JSON,
        output_file=str(output), api_url="https://api.test", client_id=None, api_key="k",
        active_only=True, include_description=True, include_mitigation=True, log_level="info",
    )
    return warnings, json.loads(output.read_text())


@pytest.mark.parametrize(("count", "truncated"), [(REPORT_LIMIT, True), (REPORT_LIMIT - 1, False)])
def test_report_warns_when_limit_reached(monkeypatch, tmp_path, count, truncated):
    findings = [{"finding_id": str(i), "severity": "LOW", "scan_type": "SAST"} for i in range(count)]
    warnings, written = _run_report(monkeypatch, tmp_path, findings)
    assert len(written) == count
    assert any("truncated" in w for w in warnings) is truncated


def test_report_tolerates_null_fields(monkeypatch, tmp_path):
    findings = [{"finding_id": "1", "severity": None, "scan_type": None, "repository_name": None, "title": None}]
    _, written = _run_report(monkeypatch, tmp_path, findings)
    assert written == findings
    markdown = generate_markdown_report(findings, "r", "b", True, True, False)
    assert "| Active | UNKNOWN | N/A | N/A |" in markdown


@pytest.mark.parametrize(("active_only", "expected"), [(True, {"is_active": True}), (False, {})])
def test_report_sends_the_active_filter_the_api_understands(monkeypatch, tmp_path, active_only, expected):
    sent = {}

    class _RecordingClient(_FakeClient):
        def get(self, url, params, headers):
            sent.update(params)
            return super().get(url, params, headers)

    monkeypatch.setattr("gerion_cli.api.auth.authenticate_with_api", lambda *a: "jwt")
    monkeypatch.setattr("httpx.Client", lambda **kw: _RecordingClient([{"finding_id": "1"}]))
    report_module.report(
        path=str(tmp_path), repo="r", branch="b", scan_type=None, severity=None, format=ReportFormat.JSON,
        output_file=str(tmp_path / "r.json"), api_url="https://api.test", client_id=None, api_key="k",
        active_only=active_only, include_description=True, include_mitigation=True, log_level="info",
    )
    assert "active_only" not in sent
    assert {k: v for k, v in sent.items() if k == "is_active"} == expected


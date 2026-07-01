import json
from types import SimpleNamespace

from nexhunt.api.project import _build_briefing


def test_ai_handoff_includes_cleartext_200_endpoints_and_enforces_scope():
    project = SimpleNamespace(
        name="Authorized engagement",
        scope=json.dumps(["*.example.test"]),
        out_of_scope=json.dumps(["admin.example.test"]),
        scope_mode="strict",
        notes="Authorized testing",
    )
    finding = SimpleNamespace(
        severity="high",
        status="confirmed",
        title="Confirmed access-control issue",
        tool="api_scanner",
        url="https://api.example.test/finding?token=clear-secret",
        created_at="2026-07-01",
    )
    rows = [
        SimpleNamespace(
            type="endpoint",
            target="",
            data=json.dumps({
                "url": "https://support.example.test/ok?key=visible",
                "status_code": 200,
                "content_type": "text/html",
            }),
        ),
        SimpleNamespace(
            type="endpoint",
            target="",
            data=json.dumps({
                "url": "https://admin.example.test/private",
                "status_code": 200,
            }),
        ),
    ]
    observed = [{
        "source": "API Scanner current workspace",
        "method": "GET",
        "url": "https://api.example.test/v1?access_token=plain",
        "status_anon": 200,
    }]

    briefing = _build_briefing(project, [finding], rows, [], observed)

    assert "key=visible" in briefing
    assert "access_token=plain" in briefing
    assert "token=clear-secret" in briefing
    assert "admin.example.test/private" not in briefing
    assert "In-scope endpoints returning HTTP 200 (2)" in briefing

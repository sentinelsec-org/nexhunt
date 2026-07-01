import asyncio

from nexhunt.adapters.api_scanner import ApiScannerAdapter, _html_doc_operation


INDEX = """
<html><head><title>Handmade API</title></head><body>
  <a href="/docs/users/create">Create user</a>
</body></html>
"""

PAGE = """
<html><body>
  <h1>/users/create</h1>
  <h2>Parameters</h2>
  <table>
    <tr><th>Name</th><th>Type</th><th>Required</th><th>Example</th><th>Description</th></tr>
    <tr><th>email</th><td>string(email)</td><td>yes</td><td>a@example.com</td><td>User email</td></tr>
    <tr><th>active</th><td>boolean</td><td>no</td><td>true</td><td>Enabled</td></tr>
  </table>
  <h2>Request</h2>
  <div class="alert alert-info">POST <u><b>https://api.example.test/v1/users</b></u>
    <span>[Content-Type: application/json]</span>
  </div>
</body></html>
"""


class _Response:
    def __init__(self, text):
        self.text = text


class _Client:
    async def get(self, url):
        assert url == "https://docs.example.test/docs/users/create"
        return _Response(PAGE)


def test_extracts_operation_from_handwritten_html():
    operation = _html_doc_operation(PAGE)
    assert operation["method"] == "POST"
    assert operation["url"] == "https://api.example.test/v1/users"
    assert operation["parameters"][0]["schema"]["format"] == "email"
    assert operation["parameters"][1]["schema"]["example"] is True


def test_builds_synthetic_openapi_contract():
    adapter = ApiScannerAdapter()
    spec = asyncio.run(adapter._html_docs_spec(
        _Client(), INDEX, "https://docs.example.test/docs", False
    ))
    assert spec["openapi"] == "3.0.0-html"
    assert spec["servers"] == [{"url": "https://api.example.test"}]
    schema = spec["paths"]["/v1/users"]["post"]["requestBody"]["content"]["application/json"]["schema"]
    assert schema["required"] == ["email"]
    assert schema["properties"]["email"]["example"] == "a@example.com"

"""
API Scanner - loads OpenAPI/Swagger contracts, builds schema-aware request
templates, and optionally probes operations anonymously and with account auth.
"""
import asyncio
import json
import logging
import re
from typing import AsyncIterator
from urllib.parse import quote, urlencode, urljoin, urlparse

import httpx

from nexhunt.adapters.base import ToolAdapter

logger = logging.getLogger(__name__)

SPEC_CANDIDATES = [
    "/openapi.json", "/swagger.json", "/v3/api-docs", "/v2/api-docs",
    "/api-docs", "/swagger/v1/swagger.json", "/openapi.yaml", "/swagger.yaml",
    "/swagger/docs/v1", "/swagger/docs",
]
HTTP_METHODS = ["get", "post", "put", "patch", "delete", "head", "options"]
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
MAX_ENDPOINTS = 500
CONCURRENCY = 10


def _parse_auth(account_auth: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    value = (account_auth or "").strip()
    if not value:
        return headers
    lines = [line.strip() for line in value.replace("\r", "").split("\n") if line.strip()]
    if len(lines) == 1 and ":" not in lines[0]:
        return {"Authorization": f"Bearer {lines[0]}"}
    for line in lines:
        if ":" in line:
            key, _, header_value = line.partition(":")
            if key.strip():
                headers[key.strip()] = header_value.strip()
    return headers


def _deref(node, root, seen=None):
    if not isinstance(node, dict):
        return node
    ref = node.get("$ref")
    if not ref or not ref.startswith("#/"):
        return node
    seen = seen or set()
    if ref in seen:
        return {}
    seen.add(ref)
    target = root
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(target, dict) or part not in target:
            return {}
        target = target[part]
    return _deref(target, root, seen)


def _normalize_schema(schema, root):
    schema = _deref(schema, root)
    if not isinstance(schema, dict):
        return {}
    if schema.get("allOf"):
        merged = {key: value for key, value in schema.items() if key != "allOf"}
        properties = dict(merged.get("properties") or {})
        required = list(merged.get("required") or [])
        for part in schema["allOf"]:
            normalized = _normalize_schema(part, root)
            properties.update(normalized.get("properties") or {})
            for name in normalized.get("required") or []:
                if name not in required:
                    required.append(name)
            for key, value in normalized.items():
                if key not in ("properties", "required") and key not in merged:
                    merged[key] = value
        if properties:
            merged["properties"] = properties
            merged["type"] = merged.get("type", "object")
        if required:
            merged["required"] = required
        schema = merged
    variants = schema.get("oneOf") or schema.get("anyOf")
    if isinstance(variants, list) and variants:
        selected = _normalize_schema(variants[0], root)
        overlay = {key: value for key, value in schema.items() if key not in ("oneOf", "anyOf")}
        schema = {**selected, **overlay}
    return schema


def _has_explicit_value(schema: dict) -> bool:
    return any(key in schema for key in ("example", "x-example", "default", "enum"))


def _sample(schema, root, name="", depth=0):
    schema = _normalize_schema(schema, root)
    if not schema or depth > 6:
        return "test"
    for key in ("example", "x-example", "default"):
        if key in schema:
            return schema[key]
    if schema.get("enum"):
        return schema["enum"][0]

    schema_type = schema.get("type")
    if not schema_type:
        if "properties" in schema:
            schema_type = "object"
        elif "items" in schema:
            schema_type = "array"

    lowered = name.lower()
    if schema_type in ("integer", "number"):
        minimum = schema.get("minimum")
        if minimum is not None:
            return max(minimum, 1) if isinstance(minimum, (int, float)) else 1
        return 1
    if schema_type == "boolean":
        return True
    if schema_type == "array":
        return [_sample(schema.get("items", {}), root, name, depth + 1)]
    if schema_type == "object":
        return _build_body(schema, root, depth + 1)

    fmt = schema.get("format", "")
    if fmt == "uuid":
        return "00000000-0000-0000-0000-000000000001"
    if fmt == "date-time":
        return "2026-01-01T00:00:00Z"
    if fmt == "date":
        return "2026-01-01"
    if fmt == "email" or "email" in lowered:
        return "test@example.com"
    if fmt in ("uri", "url") or "url" in lowered:
        return "https://example.com"
    if "phone" in lowered or "mobile" in lowered:
        return "+541100000000"
    if "password" in lowered:
        return "Test1234!"
    if "tenant" in lowered:
        return "default"
    if lowered.endswith("id") or lowered == "id":
        return 1
    if "name" in lowered:
        return "test"
    return "test"


def _build_body(schema, root, depth=0):
    schema = _normalize_schema(schema, root)
    if not schema or depth > 5:
        return {}
    if schema.get("type") == "array":
        return [_sample(schema.get("items", {}), root, "", depth + 1)]
    props = schema.get("properties", {})
    if not isinstance(props, dict) or not props:
        return _sample(schema, root, "", depth + 1) if schema.get("type") not in (None, "object") else {}
    required = set(schema.get("required") or [])
    ordered = list(required) + [key for key in props if key not in required]
    body = {}
    for key in ordered[:24]:
        child = _normalize_schema(props.get(key, {}), root)
        if child.get("readOnly"):
            continue
        try:
            if isinstance(child, dict) and (child.get("type") == "object" or "properties" in child):
                body[key] = _build_body(child, root, depth + 1)
            else:
                body[key] = _sample(child, root, key, depth + 1)
        except Exception:
            body[key] = "test"
    return body


def _schema_view(schema, root, depth=0):
    schema = _normalize_schema(schema, root)
    if not schema or depth > 4:
        return {}
    view = {}
    for key in ("type", "format", "description", "nullable", "readOnly", "writeOnly",
                "minimum", "maximum", "minLength", "maxLength", "pattern"):
        if key in schema:
            view[key] = schema[key]
    if schema.get("enum"):
        view["enum"] = schema["enum"][:30]
    for key in ("x-enumNames", "x-enum-varnames", "x-ms-enum"):
        if key in schema:
            view[key] = schema[key]
    if "example" in schema:
        view["example"] = schema["example"]
    if "default" in schema:
        view["default"] = schema["default"]
    if schema.get("required"):
        view["required"] = schema["required"]
    props = schema.get("properties")
    if isinstance(props, dict):
        view["type"] = view.get("type", "object")
        view["properties"] = {
            key: _schema_view(value, root, depth + 1)
            for key, value in list(props.items())[:60]
        }
    if isinstance(schema.get("items"), dict):
        view["type"] = view.get("type", "array")
        view["items"] = _schema_view(schema["items"], root, depth + 1)
    return view


def _field_token(value) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).casefold())


def _error_field_name(value) -> str:
    parts = [part for part in re.split(r"[.\[\]]+", str(value).lstrip("$.")) if part]
    return parts[-1] if parts else str(value)


def _is_missing_error(messages) -> bool:
    if not isinstance(messages, list):
        messages = [messages]
    text = " ".join(str(message) for message in messages).casefold()
    markers = (
        "required", "missing", "must not be empty", "must not be null",
        "is mandatory", "obligatorio", "requerido", "requerida",
    )
    return any(marker in text for marker in markers)


def _missing_form_fields(response, body) -> list[str]:
    if response.status_code != 400 or not isinstance(body, dict) or not body:
        return []
    try:
        payload = response.json()
    except Exception:
        return []
    errors = payload.get("errors") if isinstance(payload, dict) else None
    if not isinstance(errors, dict):
        return []

    sent = {_field_token(name): name for name in body}
    missing = []
    matched = set()
    for raw_name, messages in errors.items():
        form_name = _error_field_name(raw_name)
        token = _field_token(form_name)
        if token in sent and token not in matched and _is_missing_error(messages):
            missing.append(form_name)
            matched.add(token)
    return missing if len(matched) / len(sent) > 0.5 else []


def _enum_names(schema: dict) -> list[str]:
    for key in ("x-enumNames", "x-enum-varnames"):
        values = schema.get(key)
        if isinstance(values, list):
            names = [str(value) for value in values if str(value)]
            if names:
                return names
    ms_enum = schema.get("x-ms-enum")
    if isinstance(ms_enum, dict) and isinstance(ms_enum.get("values"), list):
        names = [
            str(value.get("name"))
            for value in ms_enum["values"]
            if isinstance(value, dict) and value.get("name")
        ]
        if names:
            return names
    values = schema.get("enum")
    if isinstance(values, list) and values and all(isinstance(value, str) for value in values):
        return values
    return []


def _form_scalar(value):
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return json.dumps(value, separators=(",", ":"))
    return str(value)


def _form_payloads(body: dict, schema: dict, missing_names: list[str]) -> list[dict[str, str]]:
    aliases = {_field_token(name): name for name in missing_names}
    properties = schema.get("properties", {}) if isinstance(schema, dict) else {}
    property_lookup = {
        _field_token(name): (name, value)
        for name, value in properties.items()
        if isinstance(value, dict)
    } if isinstance(properties, dict) else {}
    symbolic: dict[str, str] = {}
    numeric: dict[str, str] = {}
    has_enum_alternative = False

    for original_name, value in body.items():
        token = _field_token(original_name)
        schema_name, field_schema = property_lookup.get(token, (original_name, {}))
        form_name = aliases.get(token, schema_name)
        enum_values = field_schema.get("enum") if isinstance(field_schema, dict) else None
        enum_names = _enum_names(field_schema) if isinstance(field_schema, dict) else []
        if enum_names or isinstance(enum_values, list) and enum_values:
            has_enum_alternative = True
            symbolic[form_name] = enum_names[0] if enum_names else _form_scalar(enum_values[0])
            numeric_values = [item for item in (enum_values or []) if isinstance(item, (int, float)) and not isinstance(item, bool)]
            preferred = next((item for item in numeric_values if item != 0), None)
            numeric[form_name] = _form_scalar(preferred if preferred is not None else (numeric_values[0] if numeric_values else 1))
        else:
            symbolic[form_name] = _form_scalar(value)
            numeric[form_name] = _form_scalar(value)

    return [symbolic, numeric] if has_enum_alternative and numeric != symbolic else [symbolic]


def _parameter_contract(parameter, root):
    parameter = _deref(parameter, root)
    if not isinstance(parameter, dict):
        return None
    location = parameter.get("in", "query")
    name = str(parameter.get("name", "parameter"))
    schema = parameter.get("schema", parameter)
    schema = _deref(schema, root)
    explicit = isinstance(schema, dict) and _has_explicit_value(schema)
    if "example" in parameter:
        value = parameter["example"]
        explicit = True
    elif "x-example" in parameter:
        value = parameter["x-example"]
        explicit = True
    else:
        value = _sample(schema, root, name)
    return {
        "name": name,
        "in": location,
        "required": bool(parameter.get("required")) or location == "path",
        "description": parameter.get("description", ""),
        "value": value,
        "enabled": bool(parameter.get("required")) or location == "path" or explicit,
        "schema": _schema_view(schema, root),
    }


def _request_body_contract(operation, parameters, root, spec):
    # OpenAPI 3 requestBody.
    request_body = operation.get("requestBody")
    if request_body:
        request_body = _deref(request_body, root)
        content = request_body.get("content", {}) if isinstance(request_body, dict) else {}
        if content:
            content_type = (
                "application/json" if "application/json" in content
                else next((key for key in content if "json" in key), next(iter(content)))
            )
            media = content.get(content_type, {})
            schema = media.get("schema", {})
            value = media.get("example")
            if value is None and isinstance(media.get("examples"), dict) and media["examples"]:
                first = next(iter(media["examples"].values()))
                value = first.get("value") if isinstance(first, dict) else first
            if value is None:
                value = _build_body(schema, root)
            return {
                "required": bool(request_body.get("required")),
                "content_type": content_type,
                "value": value,
                "schema": _schema_view(schema, root),
                "source": "openapi3",
            }

    # Swagger 2 body parameter.
    for parameter in parameters:
        resolved = _deref(parameter, root)
        if isinstance(resolved, dict) and resolved.get("in") == "body":
            schema = resolved.get("schema", {})
            consumes = operation.get("consumes") or spec.get("consumes") or ["application/json"]
            content_type = (
                "application/json" if "application/json" in consumes
                else next((item for item in consumes if "json" in item), consumes[0])
            )
            return {
                "required": bool(resolved.get("required")),
                "content_type": content_type,
                "value": _build_body(schema, root),
                "schema": _schema_view(schema, root),
                "source": "swagger2",
            }

    # Swagger 2 formData parameters.
    form_parameters = []
    for parameter in parameters:
        resolved = _deref(parameter, root)
        if isinstance(resolved, dict) and resolved.get("in") == "formData":
            contract = _parameter_contract(resolved, root)
            if contract:
                form_parameters.append(contract)
    if form_parameters:
        consumes = operation.get("consumes") or spec.get("consumes") or ["application/x-www-form-urlencoded"]
        content_type = consumes[0]
        return {
            "required": any(item["required"] for item in form_parameters),
            "content_type": content_type,
            "value": {item["name"]: item["value"] for item in form_parameters if item["enabled"]},
            "schema": {"type": "object", "properties": {
                item["name"]: item["schema"] for item in form_parameters
            }},
            "source": "swagger2-form",
        }
    return None


class ApiScannerAdapter(ToolAdapter):
    name = "api_scanner"
    binary_name = ""
    result_type = "finding"

    async def check_installed(self) -> bool:
        return True

    async def inspect(self, target: str, base_override: str = "") -> dict:
        docs_url = (target or "").strip()
        if "://" not in docs_url:
            docs_url = f"https://{docs_url}"
        headers = {"User-Agent": "Mozilla/5.0 (NexHunt API Scanner)"}
        async with httpx.AsyncClient(
            verify=False, timeout=20, follow_redirects=True, headers=headers
        ) as client:
            spec, spec_url = await self._resolve_spec(client, docs_url)
        if not spec:
            raise ValueError("Could not locate an OpenAPI/Swagger spec at that URL")
        base_url = (base_override or "").strip() or self._base_url(spec, spec_url)
        all_endpoints = self._enumerate(spec, base_url)
        endpoints = all_endpoints[:MAX_ENDPOINTS]
        return {
            "spec_url": spec_url,
            "base_url": base_url,
            "title": (spec.get("info") or {}).get("title", "API"),
            "version": (spec.get("info") or {}).get("version", ""),
            "openapi_version": spec.get("openapi") or spec.get("swagger") or "",
            "endpoint_count": len(endpoints),
            "truncated": len(all_endpoints) > MAX_ENDPOINTS,
            "endpoints": endpoints,
        }

    async def run(self, target: str, options: dict) -> AsyncIterator[dict]:
        docs_url = (target or "").strip()
        if "://" not in docs_url:
            docs_url = f"https://{docs_url}"
        auth_headers = _parse_auth(options.get("account_auth", ""))
        base_override = (options.get("base_url") or "").strip()
        manual_endpoints = options.get("endpoints")
        probe_writes = bool(options.get("probe_writes", False))

        if manual_endpoints:
            base_url = base_override or docs_url
            endpoints = self._build_manual_endpoints(manual_endpoints, base_url)[:MAX_ENDPOINTS]
            yield {"_raw": True, "line": f"$ api-scan {len(endpoints)} supplied route(s) - base {base_url}"}
        else:
            yield {"_raw": True, "line": f"$ api-scan {docs_url}"}
            try:
                contract = await self.inspect(docs_url, base_override)
            except ValueError as error:
                yield {"_raw": True, "line": f"  {error}"}
                return
            base_url = contract["base_url"]
            endpoints = contract["endpoints"]
            yield {"_raw": True, "line": f"  Loaded spec: {contract['spec_url']}"}
            yield {"_raw": True, "line": f"  Base URL: {base_url}"}

        if not endpoints:
            yield {"_raw": True, "line": "  Spec has no paths to probe."}
            return
        mode = "including writes" if probe_writes else "read-only (writes skipped)"
        yield {"_raw": True, "line": f"  {len(endpoints)} operations - {mode} - {'auth pass on' if auth_headers else 'anon only'}"}

        sem = asyncio.Semaphore(CONCURRENCY)
        rows: list[dict] = []
        user_agent = {"User-Agent": "Mozilla/5.0 (NexHunt API Scanner)"}
        async with httpx.AsyncClient(
            verify=False, timeout=15, follow_redirects=False, headers=user_agent
        ) as client:
            async def probe(endpoint):
                async with sem:
                    return await self._probe(client, endpoint, auth_headers, probe_writes)

            tasks = [asyncio.create_task(probe(endpoint)) for endpoint in endpoints]
            try:
                for future in asyncio.as_completed(tasks):
                    result = await future
                    rows.append(result["row"])
                    yield {"_raw": True, "line": result["raw"]}
                    yield result["row"]
                    if result.get("finding"):
                        yield result["finding"]
            except asyncio.CancelledError:
                for task in tasks:
                    task.cancel()
                raise

        if options.get("ai_assist"):
            async for result in self._ai_triage(rows, base_url):
                yield result

    @staticmethod
    def _build_manual_endpoints(manual_endpoints, base_url):
        endpoints = []
        for item in manual_endpoints:
            if not isinstance(item, dict):
                continue
            method = str(item.get("method", "GET")).upper()
            path = str(item.get("path", "")).strip()
            if method.lower() not in HTTP_METHODS or not path:
                continue
            endpoints.append({
                "method": method,
                "path": path,
                "url": base_url.rstrip("/") + "/" + path.lstrip("/"),
                "base_url": base_url,
                "secured": bool(item.get("secured")),
                "mutating": method in WRITE_METHODS,
                "operation_id": "",
                "summary": "",
                "tags": [],
                "parameters": [],
                "body": None,
                "body_content_type": "",
                "body_schema": {},
                "request_headers": {},
            })
        return endpoints

    async def _resolve_spec(self, client, docs_url):
        try:
            response = await client.get(docs_url)
        except Exception as error:
            logger.warning("api_scanner fetch failed: %s", error)
            return None, None
        # Use the final URL after redirects as the base for relative resolution.
        effective_url = str(response.url)
        spec = self._as_spec(response.text)
        if spec:
            return spec, effective_url

        root_match = re.search(r"""rootUrl:\s*['"]([^'"]+)['"]""", response.text)
        discovery_match = re.search(r"""discoveryPaths:\s*arrayFrom\(['"]([^'"]*)['"]\)""", response.text)
        if root_match and discovery_match:
            root_url = root_match.group(1)
            for rel_path in discovery_match.group(1).split("|"):
                rel_path = rel_path.strip()
                if not rel_path:
                    continue
                candidate = root_url.rstrip("/") + "/" + rel_path.lstrip("/")
                spec = await self._try_spec(client, candidate)
                if spec:
                    return spec, candidate

        patterns = (
            r"""url:\s*['"]([^'"]+)['"]""",
            r"""urls:\s*\[\s*\{[^}]*?url:\s*['"]([^'"]+)['"]""",
            r'"url"\s*:\s*"([^"]+\.(?:json|ya?ml)[^"]*)"',
            r"""spec-url=['"]([^'"]+)['"]""",
            r"""data-url=['"]([^'"]+)['"]""",
            r"""configUrl=['"]([^'"]+)['"]""",
        )
        for pattern in patterns:
            for match in re.findall(pattern, response.text):
                candidate = urljoin(effective_url, match.replace("\\/", "/"))
                spec = await self._try_spec(client, candidate)
                if spec:
                    return spec, candidate

        # Swagger UI bundles the spec inline in swagger-ui-init.js (NestJS, etc.).
        # When the JSON spec endpoints are gated (403) the init bundle is still the
        # full spec, so pull it from there.
        for src in re.findall(r'<script[^>]+src=["\']([^"\']*swagger-ui-init[^"\']*\.js)["\']', response.text, re.I):
            candidate = urljoin(effective_url, src)
            try:
                init_response = await client.get(candidate)
            except Exception:
                continue
            spec = self._extract_embedded_spec(init_response.text)
            if spec:
                return spec, candidate

        origin = f"{urlparse(effective_url).scheme}://{urlparse(effective_url).netloc}"
        for path in SPEC_CANDIDATES:
            spec = await self._try_spec(client, origin + path)
            if spec:
                return spec, origin + path
        return None, None

    async def _try_spec(self, client, url):
        try:
            response = await client.get(url)
            return self._as_spec(response.text)
        except Exception:
            return None

    @staticmethod
    def _as_spec(text):
        value = (text or "").strip()
        if not value:
            return None
        try:
            spec = json.loads(value)
        except Exception:
            try:
                import yaml
                spec = yaml.safe_load(value)
            except Exception:
                return None
        if isinstance(spec, dict) and ("openapi" in spec or "swagger" in spec) and "paths" in spec:
            return spec
        return None

    @staticmethod
    def _extract_embedded_spec(js_text):
        # swagger-ui-init.js embeds the spec as "swaggerDoc": { ... } (or spec: {...}).
        for key in ('"swaggerDoc"', "swaggerDoc", '"spec"'):
            start = js_text.find(key)
            if start == -1:
                continue
            brace = js_text.find("{", start)
            if brace == -1:
                continue
            depth = 0
            in_str = False
            esc = False
            for i in range(brace, len(js_text)):
                ch = js_text[i]
                if in_str:
                    if esc:
                        esc = False
                    elif ch == "\\":
                        esc = True
                    elif ch == '"':
                        in_str = False
                    continue
                if ch == '"':
                    in_str = True
                elif ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        try:
                            spec = json.loads(js_text[brace:i + 1])
                        except Exception:
                            break
                        if isinstance(spec, dict) and ("openapi" in spec or "swagger" in spec) and "paths" in spec:
                            return spec
                        break
        return None

    @staticmethod
    def _base_url(spec, spec_url):
        origin = f"{urlparse(spec_url).scheme}://{urlparse(spec_url).netloc}"
        servers = spec.get("servers")
        if isinstance(servers, list) and servers:
            server_url = servers[0].get("url", "")
            variables = servers[0].get("variables", {})
            for name, config in variables.items():
                server_url = server_url.replace(f"{{{name}}}", str(config.get("default", "")))
            if server_url:
                return urljoin(origin + "/", server_url)
        if spec.get("host"):
            scheme = (spec.get("schemes") or ["https"])[0]
            return f"{scheme}://{spec['host']}{spec.get('basePath', '')}"
        return origin + (spec.get("basePath") or "")

    def _enumerate(self, spec, base_url):
        endpoints = []
        root = spec
        for path, path_item in (spec.get("paths") or {}).items():
            if not isinstance(path_item, dict):
                continue
            shared_parameters = path_item.get("parameters", [])
            for method in HTTP_METHODS:
                operation = path_item.get(method)
                if not isinstance(operation, dict):
                    continue
                raw_parameters = list(shared_parameters) + list(operation.get("parameters") or [])
                parameters = []
                for raw_parameter in raw_parameters:
                    resolved = _deref(raw_parameter, root)
                    if isinstance(resolved, dict) and resolved.get("in") in ("body", "formData"):
                        continue
                    contract = _parameter_contract(resolved, root)
                    if contract:
                        parameters.append(contract)

                request_body = _request_body_contract(operation, raw_parameters, root, spec)
                security = operation["security"] if "security" in operation else spec.get("security")
                endpoint = {
                    "method": method.upper(),
                    "path": path,
                    "base_url": base_url,
                    "secured": bool(security),
                    "mutating": method.upper() in WRITE_METHODS,
                    "operation_id": operation.get("operationId", ""),
                    "summary": operation.get("summary") or operation.get("description", ""),
                    "tags": operation.get("tags") or [],
                    "parameters": parameters,
                    "body": request_body.get("value") if request_body else None,
                    "body_content_type": request_body.get("content_type", "") if request_body else "",
                    "body_required": request_body.get("required", False) if request_body else False,
                    "body_schema": request_body.get("schema", {}) if request_body else {},
                    "request_headers": {},
                }
                endpoint["url"], endpoint["request_headers"] = self._materialize(endpoint)
                endpoints.append(endpoint)
        return endpoints

    @staticmethod
    def _materialize(endpoint):
        path = endpoint["path"]
        query = []
        headers = {}
        cookies = []
        for parameter in endpoint.get("parameters", []):
            value = parameter.get("value")
            location = parameter.get("in")
            enabled = parameter.get("enabled") or parameter.get("required")
            if location == "path":
                path = path.replace(f"{{{parameter['name']}}}", quote(str(value), safe=""))
            elif location == "query" and enabled:
                query_value = json.dumps(value) if isinstance(value, bool) else str(value)
                query.append((parameter["name"], query_value))
            elif location == "header" and enabled:
                headers[parameter["name"]] = str(value)
            elif location == "cookie" and enabled:
                cookies.append(f"{parameter['name']}={value}")
        path = re.sub(r"\{[^}]+\}", "1", path)
        if cookies:
            headers["Cookie"] = "; ".join(cookies)
        if endpoint.get("body") is not None and endpoint.get("body_content_type"):
            headers["Content-Type"] = endpoint["body_content_type"]
        url = endpoint["base_url"].rstrip("/") + "/" + path.lstrip("/")
        if query:
            url += "?" + urlencode(query)
        return url, headers

    async def _probe(self, client, endpoint, auth_headers, probe_writes):
        if endpoint["mutating"] and not probe_writes:
            row = self._row(endpoint, None, None, 0, "", "skipped_write",
                            "write method skipped - enable explicitly to probe")
            return {"row": row, "raw": f"  SKIP {endpoint['method']} {endpoint['url']} (write method)"}

        anon = await self._request(client, endpoint, {})
        authenticated = None
        if auth_headers:
            authenticated = await self._request(client, endpoint, auth_headers)
        status_anon, length, content_type, format_anon = anon
        status_auth = authenticated[0] if authenticated else None
        format_auth = authenticated[3] if authenticated else ""

        if status_anon is None:
            probe_state, note = "request_error", "request error"
        elif status_anon in (400, 415, 422):
            probe_state, note = "input_rejected", "input rejected - authorization inconclusive"
        elif status_anon in (401, 403):
            probe_state, note = "protected", "protected"
        elif 200 <= status_anon < 300 and endpoint["secured"]:
            probe_state, note = "reachable", "SECURED endpoint reachable anonymously"
        elif 200 <= status_anon < 300:
            probe_state, note = "reachable", "reachable anonymously"
        elif status_anon == 404:
            probe_state, note = "not_found", "route/resource not confirmed"
        else:
            probe_state, note = "completed", ""

        retry_formats = []
        if format_anon:
            retry_formats.append(f"anon {format_anon}")
        if format_auth:
            retry_formats.append(f"auth {format_auth}")
        if retry_formats:
            note = f"{note}; " if note else ""
            note += "body retry: " + ", ".join(retry_formats)

        row = self._row(
            endpoint, status_anon, status_auth, length, content_type, probe_state, note
        )
        raw = f"  {endpoint['method']} {endpoint['url']} -> anon {status_anon}"
        if format_anon:
            raw += f" ({format_anon})"
        if status_auth is not None:
            raw += f" | auth {status_auth}"
            if format_auth:
                raw += f" ({format_auth})"
        if note:
            raw += f" [{note}]"

        finding = None
        if isinstance(status_anon, int) and 200 <= status_anon < 300 and endpoint["secured"]:
            finding = {
                "title": f"[API] Broken access control: {endpoint['method']} {endpoint['path']} reachable without auth",
                "severity": "high",
                "vuln_type": "broken-access-control",
                "url": endpoint["url"],
                "parameter": endpoint["method"],
                "evidence": (
                    "The contract marks this operation as authenticated, but the schema-filled anonymous "
                    f"request returned {status_anon}.\nAnon status: {status_anon}\n"
                    f"Auth status: {status_auth}\nRequest body: {json.dumps(endpoint.get('body'), ensure_ascii=True)}"
                ),
                "description": "A contract-declared secured operation accepted a schema-filled anonymous request.",
                "tool": "api_scanner",
                "template_id": "api-broken-auth",
                "status": "new",
            }
        return {"row": row, "raw": raw, "finding": finding}

    @staticmethod
    def _row(endpoint, status_anon, status_auth, length, content_type, probe_state, note):
        return {
            "kind": "endpoint",
            "tool": "api_scanner",
            **endpoint,
            "auth_required": endpoint["secured"],
            "status_anon": status_anon,
            "status_auth": status_auth,
            "content_length": length,
            "content_type": content_type,
            "probe_state": probe_state,
            "note": note,
        }

    async def _request(self, client, endpoint, auth_headers):
        try:
            body = endpoint.get("body")
            content_type = endpoint.get("body_content_type", "")

            async def send(payload=body, media_type=content_type):
                headers = {**endpoint.get("request_headers", {}), **auth_headers}
                if media_type in ("application/x-www-form-urlencoded", "multipart/form-data"):
                    headers = {key: value for key, value in headers.items() if key.casefold() != "content-type"}
                kwargs = {"headers": headers}
                if payload is not None:
                    if "json" in media_type:
                        kwargs["json"] = payload
                    elif media_type == "application/x-www-form-urlencoded":
                        kwargs["data"] = payload
                    elif media_type == "multipart/form-data":
                        kwargs["files"] = {key: (None, value) for key, value in payload.items()}
                    else:
                        kwargs["content"] = payload if isinstance(payload, str) else json.dumps(payload)
                return await client.request(endpoint["method"], endpoint["url"], **kwargs)

            response = await send()
            retry_format = ""
            missing_names = _missing_form_fields(response, body) if "json" in content_type else []
            if missing_names:
                payloads = _form_payloads(body, endpoint.get("body_schema") or {}, missing_names)
                for payload in payloads:
                    response = await send(payload, "application/x-www-form-urlencoded")
                    retry_format = "form-urlencoded"
                    if response.status_code not in (400, 415, 422):
                        break
                if response.status_code in (400, 415, 422):
                    for payload in payloads:
                        response = await send(payload, "multipart/form-data")
                        retry_format = "multipart"
                        if response.status_code not in (400, 415, 422):
                            break
            return (
                response.status_code,
                len(response.content),
                response.headers.get("content-type", "").split(";")[0],
                retry_format,
            )
        except Exception as error:
            logger.debug("api scanner request failed: %s", error)
            return None, 0, "", ""

    async def _ai_triage(self, rows, base_url):
        from nexhunt.services.copilot_service import copilot_service

        lines = [
            f"{row['method']} {row['path']} -> anon {row['status_anon']}"
            + (f" / auth {row['status_auth']}" if row["status_auth"] is not None else "")
            + (f" [{row['note']}]" if row.get("note") else "")
            for row in rows[:200]
            if row.get("probe_state") != "skipped_write"
        ]
        prompt = (
            f"API scan of {base_url}. Distinguish accepted requests from input-rejected "
            "400/415/422 responses. Flag likely authorization flaws and sensitive anonymous data.\n\n"
            + "\n".join(lines)
        )
        system = (
            "You are a concise API security analyst. Never infer authorization safety from a request "
            "rejected for invalid input. Prioritize accepted anonymous requests and auth deltas."
        )
        try:
            summary = await copilot_service._dispatch(prompt, system=system, max_tokens=1200)
        except Exception as error:
            yield {"_raw": True, "line": f"  AI triage failed: {error}"}
            return
        yield {
            "title": f"[API] AI triage - {base_url}",
            "severity": "info",
            "vuln_type": "api-triage",
            "url": base_url,
            "evidence": summary,
            "description": "AI summary of the schema-aware API endpoint scan.",
            "tool": "api_scanner",
            "template_id": "api-ai-triage",
            "status": "new",
        }

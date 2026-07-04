"""Nmap adapter with safe profiles and structured XML result parsing."""
from __future__ import annotations

import re
import os
import ipaddress
import shlex
import tempfile
from pathlib import Path
from typing import AsyncIterator
from urllib.parse import urlparse
from xml.etree import ElementTree as ET

from nexhunt.adapters.base import ToolAdapter


_PROFILES = {
    "quick": {
        "ports": "top:100",
        "scripts": "none",
        "version_intensity": "2",
        "timing": "4",
    },
    "standard": {
        "ports": "top:1000",
        "scripts": "default",
        "version_intensity": "7",
        "timing": "4",
    },
    "full": {
        "ports": "-",
        "scripts": "default",
        "version_intensity": "7",
        "timing": "4",
    },
    "udp": {
        "ports": "top:100",
        "scripts": "safe",
        "version_intensity": "4",
        "timing": "4",
        "protocol": "udp",
    },
    "vuln": {
        "ports": "top:1000",
        "scripts": "vuln",
        "version_intensity": "7",
        "timing": "4",
    },
}

_PORTS_RE = re.compile(r"(?i)^(?:[tusp]:)?\d+(?:-\d*)?(?:,(?:[tusp]:)?\d+(?:-\d*)?)*$")
_HOST_RE = re.compile(r"^[A-Za-z0-9_.:\-/%]+$")
_SCRIPT_RE = re.compile(r"^[A-Za-z0-9_.,+*/!?\-\s]+$")


def normalize_target(target: str) -> str:
    raw = target.strip()
    if not raw:
        raise ValueError("Nmap target is required")
    if "://" in raw:
        parsed = urlparse(raw)
        raw = parsed.hostname or ""
    else:
        raw = raw.rstrip("/")
        if "/" in raw:
            try:
                ipaddress.ip_network(raw, strict=False)
            except ValueError:
                raw = raw.split("/", 1)[0]
        if raw.startswith("[") and "]" in raw:
            raw = raw[1:raw.index("]")]
        elif raw.count(":") == 1:
            host, possible_port = raw.rsplit(":", 1)
            if possible_port.isdigit():
                raw = host
    if not raw or raw.startswith("-") or any(char.isspace() for char in raw) or not _HOST_RE.fullmatch(raw):
        raise ValueError("Invalid hostname, IP address or CIDR target")
    return raw


def _bool(options: dict, key: str, default: bool = False) -> bool:
    value = options.get(key, default)
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _ports_args(value: str) -> list[str]:
    raw = value.strip()
    if raw.startswith("-p"):
        raw = raw[2:].strip()
    if raw in {"", "top:1000"}:
        return ["--top-ports", "1000"]
    if raw.startswith("top:") and raw[4:].isdigit():
        count = max(1, min(int(raw[4:]), 65535))
        return ["--top-ports", str(count)]
    if raw == "-":
        return ["-p-"]
    if not _PORTS_RE.fullmatch(raw):
        raise ValueError("Ports must be a number, range, comma list, '-' or top:N")
    return ["-p", raw]


def build_nmap_command(target: str, options: dict, xml_path: str) -> tuple[list[str], str]:
    clean_target = normalize_target(target)
    profile_name = str(options.get("profile") or "standard").lower()
    profile = _PROFILES.get(profile_name, _PROFILES["standard"])

    protocol = str(options.get("protocol") or profile.get("protocol") or "tcp").lower()
    scan_type = str(options.get("scan_type") or "connect").lower()
    if protocol == "udp":
        scan_flags = ["-sU"]
    elif protocol == "both":
        scan_flags = ["-sS" if scan_type == "syn" else "-sT", "-sU"]
    else:
        scan_flags = ["-sS" if scan_type == "syn" else "-sT"]

    timing = str(options.get("timing") or profile.get("timing") or "4")
    if timing not in {"0", "1", "2", "3", "4", "5"}:
        timing = "4"
    intensity = str(options.get("version_intensity") or profile.get("version_intensity") or "7")
    try:
        intensity = str(max(0, min(int(intensity), 9)))
    except ValueError:
        intensity = "7"

    cmd = ["nmap", *scan_flags, "-sV", "--version-intensity", intensity, "--reason", f"-T{timing}"]
    cmd.extend(_ports_args(str(options.get("ports") or profile.get("ports") or "top:1000")))

    scripts = str(options.get("scripts") or profile.get("scripts") or "default").strip().lower()
    if scripts == "default":
        cmd.append("-sC")
    elif scripts == "safe":
        cmd.extend(["--script", "safe"])
    elif scripts == "discovery":
        cmd.extend(["--script", "discovery,safe"])
    elif scripts == "vuln":
        cmd.extend(["--script", "vuln,safe"])
    elif scripts not in {"", "none"}:
        if not _SCRIPT_RE.fullmatch(scripts):
            raise ValueError("Invalid Nmap script expression")
        cmd.extend(["--script", scripts])

    script_args = str(options.get("script_args") or "").strip()
    if script_args:
        cmd.extend(["--script-args", script_args])
    if _bool(options, "skip_discovery"):
        cmd.append("-Pn")
    if _bool(options, "os_detection"):
        cmd.extend(["-O", "--osscan-limit"])
    if _bool(options, "traceroute"):
        cmd.append("--traceroute")
    if _bool(options, "no_dns"):
        cmd.append("-n")
    if _bool(options, "ipv6") or ":" in clean_target:
        cmd.append("-6")

    min_rate = str(options.get("min_rate") or "").strip()
    if min_rate.isdigit():
        cmd.extend(["--min-rate", str(max(1, min(int(min_rate), 100000)))])
    max_retries = str(options.get("max_retries") or "").strip()
    if max_retries.isdigit():
        cmd.extend(["--max-retries", str(max(0, min(int(max_retries), 20)))])
    host_timeout = str(options.get("host_timeout") or "").strip()
    if host_timeout and re.fullmatch(r"\d+[smh]?", host_timeout, re.IGNORECASE):
        cmd.extend(["--host-timeout", host_timeout])

    legacy_flags = str(options.get("flags") or "").strip()
    if legacy_flags:
        try:
            cmd.extend(shlex.split(legacy_flags))
        except ValueError:
            pass
    extra_flags = str(options.get("extra_args") or "").strip()
    if extra_flags:
        try:
            cmd.extend(shlex.split(extra_flags))
        except ValueError:
            pass

    cmd.extend(["--open", "-oX", xml_path, clean_target])
    return cmd, clean_target


def _scripts(element: ET.Element | None) -> tuple[str, list[dict]]:
    if element is None:
        return "", []
    rows = []
    for script in element.findall("script"):
        script_id = script.get("id", "script")
        output = script.get("output", "").strip()
        rows.append({"id": script_id, "output": output})
    text = "\n\n".join(f"[{row['id']}]\n{row['output']}" for row in rows if row["output"])
    return text, rows


def parse_nmap_xml(xml_path: str, profile: str = "standard") -> list[dict]:
    path = Path(xml_path)
    if not path.is_file() or path.stat().st_size == 0:
        return []
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        return []

    results: list[dict] = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        addresses = {
            node.get("addrtype", "unknown"): node.get("addr", "")
            for node in host.findall("address") if node.get("addr")
        }
        ip = addresses.get("ipv4") or addresses.get("ipv6") or addresses.get("mac") or "unknown"
        hostname_nodes = host.findall("./hostnames/hostname")
        hostname = next((node.get("name", "") for node in hostname_nodes if node.get("type") == "user"), "")
        if not hostname:
            hostname = next((node.get("name", "") for node in hostname_nodes if node.get("name")), "")

        os_matches = []
        for node in host.findall("./os/osmatch")[:5]:
            os_matches.append({
                "name": node.get("name", ""),
                "accuracy": int(node.get("accuracy", "0") or 0),
                "line": node.get("line", ""),
            })
        host_script_text, host_script_rows = _scripts(host.find("hostscript"))
        trace = [
            {"ttl": hop.get("ttl", ""), "ip": hop.get("ipaddr", ""), "host": hop.get("host", ""), "rtt": hop.get("rtt", "")}
            for hop in host.findall("./trace/hop")
        ]

        for port in host.findall("./ports/port"):
            state_node = port.find("state")
            state = state_node.get("state", "unknown") if state_node is not None else "unknown"
            if not state.startswith("open"):
                continue
            service_node = port.find("service")
            service = service_node.attrib if service_node is not None else {}
            cpes = [node.text or "" for node in port.findall("./service/cpe") if node.text]
            script_text, script_rows = _scripts(port)
            version_parts = [service.get("product", ""), service.get("version", ""), service.get("extrainfo", "")]
            version = " ".join(part for part in version_parts if part).strip() or None
            results.append({
                "_raw": False,
                "ip": ip,
                "hostname": hostname,
                "addresses": addresses,
                "port": int(port.get("portid", "0") or 0),
                "proto": port.get("protocol", "tcp"),
                "state": state,
                "reason": state_node.get("reason", "") if state_node is not None else "",
                "service": service.get("name") or "unknown",
                "product": service.get("product") or "",
                "version": version,
                "extra_info": service.get("extrainfo") or "",
                "service_tunnel": service.get("tunnel") or "",
                "device_type": service.get("devicetype") or "",
                "service_os": service.get("ostype") or "",
                "confidence": int(service.get("conf", "0") or 0),
                "cpes": cpes,
                "scripts": script_text,
                "script_results": script_rows,
                "host_scripts": host_script_text,
                "host_script_results": host_script_rows,
                "os_matches": os_matches,
                "trace": trace,
                "scan_profile": profile,
            })
    return results


def _scan_flag(options: dict) -> str:
    protocol = str(options.get("protocol") or "tcp").lower()
    if protocol == "udp":
        return "-sU"
    return "-sS" if str(options.get("scan_type") or "connect").lower() == "syn" else "-sT"


def _common_flags(options: dict, clean_target: str) -> list[str]:
    flags: list[str] = []
    if _bool(options, "skip_discovery", True):  # assume an authorized, known-up target
        flags.append("-Pn")
    if _bool(options, "no_dns", True):
        flags.append("-n")
    if _bool(options, "ipv6") or ":" in clean_target:
        flags.append("-6")
    return flags


def build_discovery_command(target: str, options: dict, xml_path: str) -> tuple[list[str], str]:
    """Phase 1: sweep every port fast, no service/script probes, just find what's open."""
    clean_target = normalize_target(target)
    timing = str(options.get("timing") or "4")
    if timing not in {"0", "1", "2", "3", "4", "5"}:
        timing = "4"
    cmd = ["nmap", _scan_flag(options), f"-T{timing}", "--open", *_common_flags(options, clean_target)]
    # UDP has no fast all-port equivalent, so cap it; TCP sweeps the full range.
    cmd.extend(["--top-ports", "200"] if str(options.get("protocol") or "tcp").lower() == "udp" else ["-p-"])
    min_rate = str(options.get("min_rate") or "1800").strip()
    if min_rate.isdigit():
        cmd.extend(["--min-rate", str(max(1, min(int(min_rate), 100000)))])
    cmd.extend(["-oX", xml_path, clean_target])
    return cmd, clean_target


def build_deep_command(target: str, ports_csv: str, options: dict, xml_path: str) -> tuple[list[str], str]:
    """Phase 2: full service, default and vuln scripts against the open ports only."""
    clean_target = normalize_target(target)
    ports_csv = ports_csv.strip()
    if not _PORTS_RE.fullmatch(ports_csv):
        raise ValueError("Deep scan ports must be numbers, ranges or a comma list")
    timing = str(options.get("timing") or "4")
    if timing not in {"0", "1", "2", "3", "4", "5"}:
        timing = "4"
    intensity = str(options.get("version_intensity") or "7")
    try:
        intensity = str(max(0, min(int(intensity), 9)))
    except ValueError:
        intensity = "7"
    cmd = [
        "nmap", _scan_flag(options), "-sV", "--version-intensity", intensity,
        "-sC", "--script", "default,vuln", "--reason", f"-T{timing}",
        "-p", ports_csv, "--open", *_common_flags(options, clean_target),
    ]
    if _bool(options, "os_detection"):
        cmd.extend(["-O", "--osscan-limit"])
    script_args = str(options.get("script_args") or "").strip()
    if script_args:
        cmd.extend(["--script-args", script_args])
    cmd.extend(["-oX", xml_path, clean_target])
    return cmd, clean_target


class NmapAdapter(ToolAdapter):
    name = "nmap"
    binary_name = "nmap"
    result_type = "port"

    async def run(self, target: str, options: dict) -> AsyncIterator[dict]:
        profile = str(options.get("profile") or "auto").lower()
        if profile == "auto":
            async for item in self._run_two_phase(target, options):
                yield item
            return
        if profile == "discovery":
            async for item in self._run_discovery(target, options):
                yield item
            return
        if profile == "deep":
            async for item in self._run_deep(target, options):
                yield item
            return

        fd, xml_path = tempfile.mkstemp(prefix="nexhunt-nmap-", suffix=".xml")
        os.close(fd)
        Path(xml_path).unlink(missing_ok=True)
        try:
            cmd, clean_target = build_nmap_command(target, options, xml_path)
            display_cmd = ["<temporary.xml>" if part == xml_path else part for part in cmd]
            yield {"_raw": True, "line": "$ " + " ".join(shlex.quote(part) for part in display_cmd)}
            yield {"_raw": True, "line": f"  Profile: {profile}  Target: {clean_target}"}
            timeout = 1800 if profile == "full" else 900
            async for line in self._run_subprocess(cmd, timeout=timeout, merge_stderr=True):
                yield {"_raw": True, "line": line}
            parsed = parse_nmap_xml(xml_path, profile)
            yield {"_raw": True, "line": f"  Structured results: {len(parsed)} open ports"}
            for result in parsed:
                yield result
        finally:
            Path(xml_path).unlink(missing_ok=True)

    async def _run_two_phase(self, target: str, options: dict) -> AsyncIterator[dict]:
        fd1, xml1 = tempfile.mkstemp(prefix="nexhunt-nmap-p1-", suffix=".xml")
        fd2, xml2 = tempfile.mkstemp(prefix="nexhunt-nmap-p2-", suffix=".xml")
        os.close(fd1)
        os.close(fd2)
        Path(xml1).unlink(missing_ok=True)
        Path(xml2).unlink(missing_ok=True)
        try:
            all_ports = str(options.get("protocol") or "tcp").lower() != "udp"
            cmd1, clean_target = build_discovery_command(target, options, xml1)
            yield {"_raw": True, "line": f"  Phase 1/2 — Fast port sweep ({'all 65,535 TCP ports' if all_ports else 'top 200 UDP ports'}) on {clean_target}"}
            yield {"_raw": True, "line": "$ " + " ".join(shlex.quote("<phase1.xml>" if p == xml1 else p) for p in cmd1)}
            async for line in self._run_subprocess(cmd1, timeout=1200, merge_stderr=True):
                yield {"_raw": True, "line": line}

            open_ports = sorted({r["port"] for r in parse_nmap_xml(xml1, "auto") if r.get("port")})
            if not open_ports:
                yield {"_raw": True, "line": "  No open ports found — nothing to probe deeper."}
                return
            ports_csv = ",".join(str(p) for p in open_ports)
            yield {"_raw": True, "line": f"  Phase 1 done — {len(open_ports)} open port(s): {ports_csv}"}

            cmd2, _ = build_deep_command(target, ports_csv, options, xml2)
            yield {"_raw": True, "line": f"  Phase 2/2 — Deep scan (service + default + vuln scripts) on {len(open_ports)} open port(s)"}
            yield {"_raw": True, "line": "$ " + " ".join(shlex.quote("<phase2.xml>" if p == xml2 else p) for p in cmd2)}
            async for line in self._run_subprocess(cmd2, timeout=1800, merge_stderr=True):
                yield {"_raw": True, "line": line}

            parsed = parse_nmap_xml(xml2, "auto")
            yield {"_raw": True, "line": f"  Structured results: {len(parsed)} open port(s) with service + script data"}
            for result in parsed:
                yield result
        finally:
            Path(xml1).unlink(missing_ok=True)
            Path(xml2).unlink(missing_ok=True)

    async def _run_discovery(self, target: str, options: dict) -> AsyncIterator[dict]:
        """Fast sweep only — find open ports across the target, no deep probing."""
        fd, xml_path = tempfile.mkstemp(prefix="nexhunt-nmap-disc-", suffix=".xml")
        os.close(fd)
        Path(xml_path).unlink(missing_ok=True)
        try:
            all_ports = str(options.get("protocol") or "tcp").lower() != "udp"
            cmd, clean_target = build_discovery_command(target, options, xml_path)
            yield {"_raw": True, "line": f"  Fast sweep ({'all 65,535 TCP ports' if all_ports else 'top 200 UDP ports'}) on {clean_target}"}
            yield {"_raw": True, "line": "$ " + " ".join(shlex.quote("<sweep.xml>" if p == xml_path else p) for p in cmd)}
            async for line in self._run_subprocess(cmd, timeout=1200, merge_stderr=True):
                yield {"_raw": True, "line": line}
            parsed = parse_nmap_xml(xml_path, "discovery")
            yield {"_raw": True, "line": f"  {len(parsed)} open port(s) found — run Deep scan on a host for service + vuln detail"}
            for result in parsed:
                yield result
        finally:
            Path(xml_path).unlink(missing_ok=True)

    async def _run_deep(self, target: str, options: dict) -> AsyncIterator[dict]:
        """Deep service + default + vuln scripts against a supplied open-port list."""
        ports_csv = str(options.get("ports") or "").strip()
        if not ports_csv:
            yield {"_raw": True, "line": "  Deep scan needs open ports — run a Fast sweep first."}
            return
        fd, xml_path = tempfile.mkstemp(prefix="nexhunt-nmap-deep-", suffix=".xml")
        os.close(fd)
        Path(xml_path).unlink(missing_ok=True)
        try:
            cmd, clean_target = build_deep_command(target, ports_csv, options, xml_path)
            yield {"_raw": True, "line": f"  Deep scan (service + default + vuln scripts) on {clean_target} — ports {ports_csv}"}
            yield {"_raw": True, "line": "$ " + " ".join(shlex.quote("<deep.xml>" if p == xml_path else p) for p in cmd)}
            async for line in self._run_subprocess(cmd, timeout=1800, merge_stderr=True):
                yield {"_raw": True, "line": line}
            parsed = parse_nmap_xml(xml_path, "deep")
            yield {"_raw": True, "line": f"  Structured results: {len(parsed)} open port(s) with service + script data"}
            for result in parsed:
                yield result
        finally:
            Path(xml_path).unlink(missing_ok=True)

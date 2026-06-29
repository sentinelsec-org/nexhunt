import tempfile
import unittest
from pathlib import Path

from nexhunt.adapters.nmap import build_nmap_command, normalize_target, parse_nmap_xml


NMAP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up" reason="syn-ack" />
    <address addr="10.20.30.40" addrtype="ipv4" />
    <hostnames><hostname name="api.internal.test" type="PTR" /></hostnames>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack" />
        <service name="https" product="nginx" version="1.24.0" tunnel="ssl" conf="10">
          <cpe>cpe:/a:igor_sysoev:nginx:1.24.0</cpe>
        </service>
        <script id="ssl-cert" output="CN=api.internal.test" />
      </port>
      <port protocol="tcp" portid="22"><state state="closed" reason="reset" /></port>
    </ports>
    <os><osmatch name="Linux 5.x" accuracy="96" line="1" /></os>
    <hostscript><script id="host-info" output="environment: staging" /></hostscript>
    <trace><hop ttl="1" ipaddr="10.20.30.1" rtt="1.2" host="gateway" /></trace>
  </host>
</nmaprun>
"""


class NmapAdapterTests(unittest.TestCase):
    def test_target_normalization(self):
        self.assertEqual(normalize_target("https://example.com:8443/path"), "example.com")
        self.assertEqual(normalize_target("10.0.0.0/24"), "10.0.0.0/24")
        with self.assertRaises(ValueError):
            normalize_target("--script malicious")

    def test_standard_and_vuln_commands(self):
        command, target = build_nmap_command("example.com", {"profile": "standard"}, "/tmp/out.xml")
        self.assertEqual(target, "example.com")
        self.assertIn("-sT", command)
        self.assertIn("-sC", command)
        self.assertIn("--top-ports", command)
        self.assertEqual(command[-1], "example.com")

        command, _ = build_nmap_command("example.com", {
            "profile": "vuln", "skip_discovery": "true", "os_detection": "true",
            "ports": "80,443,8443", "timing": "3",
        }, "/tmp/out.xml")
        self.assertIn("vuln,safe", command)
        self.assertIn("-Pn", command)
        self.assertIn("-O", command)
        self.assertIn("80,443,8443", command)
        self.assertIn("-T3", command)

    def test_xml_results_include_fingerprints_and_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nmap.xml"
            path.write_text(NMAP_XML)
            results = parse_nmap_xml(str(path), "standard")
        self.assertEqual(len(results), 1)
        row = results[0]
        self.assertEqual(row["ip"], "10.20.30.40")
        self.assertEqual(row["hostname"], "api.internal.test")
        self.assertEqual(row["port"], 443)
        self.assertEqual(row["product"], "nginx")
        self.assertIn("1.24.0", row["version"])
        self.assertIn("ssl-cert", row["scripts"])
        self.assertEqual(row["os_matches"][0]["accuracy"], 96)
        self.assertEqual(row["trace"][0]["host"], "gateway")


if __name__ == "__main__":
    unittest.main()

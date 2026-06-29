import asyncio
import os
import shutil
import subprocess
import tempfile
import threading
import unittest
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from nexhunt.services.repository_intelligence import (
    detect_providers,
    extract_architecture,
    materialize_working_tree,
    normalize_target,
    recover_repository,
    scan_secrets,
)


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, _format, *args):
        pass


class RepositoryIntelligenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp.name)
        subprocess.run(["git", "init", "-q"], cwd=self.repo, check=True)
        subprocess.run(["git", "config", "user.email", "nexhunt@test.local"], cwd=self.repo, check=True)
        subprocess.run(["git", "config", "user.name", "NexHunt Test"], cwd=self.repo, check=True)

    def tearDown(self):
        self.temp.cleanup()

    def commit(self, message: str):
        subprocess.run(["git", "add", "-A"], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-qm", message], cwd=self.repo, check=True)

    def test_normalize_target_accepts_git_artifact_urls(self):
        base, git_url = normalize_target("https://example.com/app/.git/HEAD")
        self.assertEqual(base, "https://example.com/app")
        self.assertEqual(git_url, "https://example.com/app/.git/")

    def test_current_and_deleted_secrets_are_returned_in_cleartext(self):
        (self.repo / ".env").write_text("DB_PASSWORD=historic-password-4815\n")
        self.commit("add configuration")
        (self.repo / ".env").unlink()
        (self.repo / "settings.py").write_text("API_KEY = 'current-api-key-7391'\n")
        self.commit("rotate configuration")

        secrets, history = asyncio.run(scan_secrets(self.repo, 50))
        raw = {item["raw"] for item in secrets}
        self.assertIn("historic-password-4815", raw)
        self.assertIn("current-api-key-7391", raw)
        self.assertTrue(any(item["raw"] == "historic-password-4815" and item["historical"] for item in secrets))
        self.assertGreaterEqual(history["commits_scanned"], 2)

    def test_authenticated_remote_is_reported_as_cleartext_secret(self):
        recovered = self.repo / ".git" / "config-recovered"
        recovered.write_text(
            "[remote \"origin\"]\n"
            "    url = https://oauth2:visible-token-4815@gitlab.example/team/app.git\n"
        )
        secrets, _ = asyncio.run(scan_secrets(self.repo, 0))
        self.assertTrue(any(
            item["detector"] == "Authenticated URL" and "visible-token-4815" in item["raw"]
            for item in secrets
        ))

    def test_architecture_and_provider_detection(self):
        (self.repo / "compose.yml").write_text(
            "DATABASE_URL=postgres://admin:clear-pass@db.internal.example:5432/app\n"
            "API_URL=https://api.internal.example/v1\n"
        )
        architecture = extract_architecture(self.repo)
        self.assertIn("db.internal.example", architecture["hosts"])
        self.assertIn("api.internal.example", architecture["hosts"])
        self.assertTrue(architecture["services"][0]["credentials_exposed"])

        providers = detect_providers(["git@gitlab.com:team/app.git"], [])
        self.assertEqual(providers[0]["provider"], "gitlab")

    def test_materialization_never_executes_hooks_or_creates_symlinks(self):
        (self.repo / "safe.txt").write_text("recovered source\n")
        os.symlink("/etc/passwd", self.repo / "external-link")
        self.commit("add source and link")
        marker = self.repo / "checkout-executed"
        hook = self.repo / ".git" / "hooks" / "post-checkout"
        hook.write_text(f"#!/bin/sh\ntouch {marker}\n")
        hook.chmod(0o700)

        count = asyncio.run(materialize_working_tree(self.repo))

        self.assertGreaterEqual(count, 2)
        self.assertFalse(marker.exists())
        self.assertFalse((self.repo / "external-link").is_symlink())
        self.assertEqual((self.repo / "external-link").read_text(), "/etc/passwd")

    @unittest.skipUnless(shutil.which("git-dumper"), "git-dumper is not installed")
    def test_end_to_end_recovery_blocks_malicious_git_filter(self):
        marker = self.repo / ".git" / "malicious-filter-executed"
        marker.unlink(missing_ok=True)
        (self.repo / ".gitattributes").write_text("* filter=hostile\n")
        (self.repo / "app.env").write_text("API_KEY=end-to-end-clear-secret-7391\n")
        subprocess.run(
            ["git", "config", "filter.hostile.smudge", f"touch {marker} && cat"],
            cwd=self.repo, check=True,
        )
        self.commit("exposed repository")
        self.assertFalse(marker.exists(), "test fixture executed the filter before recovery")
        handler = partial(QuietHandler, directory=str(self.repo))
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        destination = self.repo.parent / "recovered"
        try:
            result = asyncio.run(recover_repository(
                f"http://127.0.0.1:{server.server_port}/.git/", destination,
            ))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertFalse(marker.exists())
        self.assertEqual((destination / "app.env").read_text(), "API_KEY=end-to-end-clear-secret-7391\n")
        self.assertGreaterEqual(result["commits"], 1)


if __name__ == "__main__":
    unittest.main()

import asyncio
import json
import sys
import unittest
from unittest.mock import patch

from nexhunt.adapters.httpx_adapter import HttpxAdapter
from nexhunt.api import recon
from nexhunt.schemas.recon import HttpxProbeRequest


class HttpxAdapterTests(unittest.TestCase):
    def test_nonzero_exit_surfaces_stderr(self):
        adapter = HttpxAdapter()

        async def consume():
            async for _ in adapter._run_subprocess(
                [sys.executable, "-c", "import sys; print('bad flag', file=sys.stderr); sys.exit(3)"],
                check_exit=True,
            ):
                pass

        with self.assertRaisesRegex(RuntimeError, "bad flag"):
            asyncio.run(consume())

    def test_current_httpx_json_shape_is_normalized(self):
        adapter = HttpxAdapter()
        payload = json.dumps({
            "url": "https://example.test",
            "input": "example.test",
            "status_code": 200,
            "content_type": "text/html",
            "title": "Example",
            "tech": ["HSTS"],
            "a": ["192.0.2.10"],
        })

        async def fake_run(*_args, **_kwargs):
            yield payload

        adapter._run_subprocess = fake_run  # type: ignore[method-assign]

        async def collect():
            return [item async for item in adapter.run("example.test", {}) if not item.get("_raw")]

        self.assertEqual(asyncio.run(collect()), [{
            "url": "https://example.test",
            "host": "example.test",
            "source": "httpx",
            "status_code": 200,
            "content_type": "text/html",
            "title": "Example",
            "technologies": ["HSTS"],
            "ip": "192.0.2.10",
            "alive": True,
        }])

    def test_probe_endpoint_reports_job_and_result_count(self):
        events = []

        class FakeAdapter:
            async def check_installed(self):
                return True

            async def run(self, _target, _options):
                yield {"_raw": True, "line": "$ httpx ..."}
                yield {
                    "url": "https://example.test", "host": "example.test",
                    "status_code": 200, "alive": True,
                }

        async def capture(channel, data, event="update"):
            events.append((channel, data))

        async def ignore_save(*_args, **_kwargs):
            return None

        async def exercise():
            response = await recon.run_httpx_probe(HttpxProbeRequest(
                targets=["example.test"], project_id="project-1",
            ))
            task = recon._RECON_JOBS[response["job_id"]]
            await task
            return response

        with (
            patch.object(recon, "get_adapter", return_value=FakeAdapter()),
            patch.object(recon.ws_manager, "broadcast", side_effect=capture),
            patch.object(recon, "_save_recon_result", side_effect=ignore_save),
        ):
            response = asyncio.run(exercise())

        statuses = [data for channel, data in events if channel == "tool_status"]
        self.assertEqual(statuses[0]["job_id"], response["job_id"])
        self.assertEqual(statuses[-1]["event"], "completed")
        self.assertEqual(statuses[-1]["result_count"], 1)


if __name__ == "__main__":
    unittest.main()

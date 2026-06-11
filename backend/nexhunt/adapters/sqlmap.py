from typing import AsyncIterator
from nexhunt.adapters.base import ToolAdapter


class SqlmapAdapter(ToolAdapter):
    name = "sqlmap"
    binary_name = "sqlmap"
    result_type = "finding"

    async def run(self, target: str, options: dict) -> AsyncIterator[dict]:
        level = options.get("level", "3")
        risk = options.get("risk", "2")
        technique = options.get("technique", "")
        dbms = options.get("dbms", "")
        cookie = options.get("cookie", "")
        data = options.get("data", "")
        headers = options.get("headers", "")

        cmd = [
            self.binary_name,
            "-u", target,
            "--batch",
            "--random-agent",
            "--level", str(level),
            "--risk", str(risk),
            "--output-dir", "/tmp/sqlmap_nexhunt",
        ]

        if technique:
            cmd.extend(["--technique", technique])
        if dbms:
            cmd.extend(["--dbms", dbms])
        if cookie:
            cmd.extend(["--cookie", cookie])
        if data:
            cmd.extend(["--data", data])
        if headers:
            cmd.extend(["--headers", headers])
        if options.get("forms"):
            cmd.append("--forms")
        if options.get("crawl"):
            cmd.extend(["--crawl", "2"])
        if options.get("dump"):
            cmd.append("--dump")
        if options.get("dbs"):
            cmd.append("--dbs")

        cmd = self._with_extra_args(cmd, options)
        yield {"_raw": True, "line": "$ " + " ".join(cmd)}
        async for line in self._run_subprocess(cmd, timeout=600):
            yield line

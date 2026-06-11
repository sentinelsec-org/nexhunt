"""
Checks which external tools are installed by looking for their binaries in PATH.
"""
import shutil
import asyncio
import logging

logger = logging.getLogger(__name__)

ALL_TOOLS = [
    # Recon
    {"name": "subfinder",    "binary": "subfinder",    "category": "recon",   "install": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
    {"name": "amass",        "binary": "amass",        "category": "recon",   "install": "go install github.com/owasp-amass/amass/v4/...@master"},
    {"name": "httpx",        "binary": "httpx",        "category": "recon",   "install": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"},
    {"name": "nmap",         "binary": "nmap",         "category": "recon",   "install": "sudo apt install nmap"},
    {"name": "whatweb",      "binary": "whatweb",      "category": "recon",   "install": "sudo apt install whatweb"},
    {"name": "waybackurls",  "binary": "waybackurls",  "category": "recon",   "install": "go install github.com/tomnomnom/waybackurls@latest"},
    {"name": "gau",          "binary": "gau",          "category": "recon",   "install": "go install github.com/lc/gau/v2/cmd/gau@latest"},
    {"name": "katana",       "binary": "katana",       "category": "recon",   "install": "go install github.com/projectdiscovery/katana/cmd/katana@latest"},
    {"name": "paramspider",  "binary": "paramspider",  "category": "recon",   "install": "pip3 install paramspider"},
    {"name": "arjun",        "binary": "arjun",        "category": "recon",   "install": "pip3 install arjun"},
    # Scanner
    {"name": "nuclei",       "binary": "nuclei",       "category": "scanner", "install": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
    {"name": "nikto",        "binary": "nikto",        "category": "scanner", "install": "sudo apt install nikto"},
    {"name": "ffuf",         "binary": "ffuf",         "category": "scanner", "install": "go install github.com/ffuf/ffuf/v2@latest"},
    {"name": "gobuster",     "binary": "gobuster",     "category": "scanner", "install": "go install github.com/OJ/gobuster/v3@latest"},
    {"name": "dirsearch",    "binary": "dirsearch",    "category": "scanner", "install": "pip3 install dirsearch"},
    # Exploit
    {"name": "sqlmap",       "binary": "sqlmap",       "category": "exploit", "install": "sudo apt install sqlmap"},
    {"name": "dalfox",       "binary": "dalfox",       "category": "exploit", "install": "go install github.com/hahwul/dalfox/v2@latest"},
    {"name": "xsstrike",     "binary": "xsstrike",     "category": "exploit", "install": "pip3 install xsstrike"},
    {"name": "commix",       "binary": "commix",       "category": "exploit", "install": "sudo apt install commix"},
]


async def check_all_tools() -> list[dict]:
    """Return status of all tools."""
    results = []
    for tool in ALL_TOOLS:
        binary = tool["binary"]
        path = shutil.which(binary)
        version = None

        if path:
            # Try to get version quickly
            try:
                proc = await asyncio.create_subprocess_exec(
                    binary, "--version",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=3)
                raw = (stdout or stderr).decode().strip()
                version = raw.split("\n")[0][:40] if raw else None
            except Exception:
                version = None

        results.append({
            "name": tool["name"],
            "category": tool["category"],
            "installed": path is not None,
            "version": version,
            "path": path,
            "install_cmd": tool["install"],
        })

    return results

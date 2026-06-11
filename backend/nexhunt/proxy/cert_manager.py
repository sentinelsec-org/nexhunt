"""
CA certificate management for HTTPS interception.
mitmproxy auto-generates its CA cert in ~/.mitmproxy/ on first run.
This module exposes the cert path so the user can download and install it.
"""
import os
import shutil
import logging

logger = logging.getLogger(__name__)

MITMPROXY_DIR = os.path.expanduser("~/.mitmproxy")
CERT_FILE = os.path.join(MITMPROXY_DIR, "mitmproxy-ca-cert.pem")
CERT_CRT = os.path.join(MITMPROXY_DIR, "mitmproxy-ca-cert.crt")  # Windows/Android format


def get_cert_path() -> str | None:
    """Return the path to the CA cert if it exists."""
    if os.path.exists(CERT_FILE):
        return CERT_FILE
    if os.path.exists(CERT_CRT):
        return CERT_CRT
    return None


def cert_exists() -> bool:
    return get_cert_path() is not None


def get_install_instructions() -> dict:
    """Return OS-specific instructions for installing the CA cert."""
    return {
        "linux": [
            "sudo cp ~/.mitmproxy/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/nexhunt-ca.crt",
            "sudo update-ca-certificates",
            "# For Firefox: Preferences > Privacy > Certificates > Import"
        ],
        "browser": [
            "1. Download the cert using the button above",
            "2. Go to browser Settings > Privacy & Security > Certificates",
            "3. Import the downloaded cert",
            "4. Trust it for identifying websites"
        ]
    }

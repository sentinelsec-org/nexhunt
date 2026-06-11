"""Local persistence of license state at ~/.nexhunt/license.json."""
import json
import logging
import os
import time

from nexhunt.config import settings

logger = logging.getLogger(__name__)

_PATH = os.path.join(settings.db_dir, "license.json")


def load() -> dict:
    try:
        with open(_PATH) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def save(data: dict) -> None:
    data = {**data, "updated_at": int(time.time())}
    try:
        with open(_PATH, "w") as f:
            json.dump(data, f, indent=2)
        os.chmod(_PATH, 0o600)
    except OSError as e:
        logger.warning(f"Could not persist license state: {e}")


def clear() -> None:
    try:
        os.remove(_PATH)
    except OSError:
        pass

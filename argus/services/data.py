import json
from pathlib import Path

DEFAULT_DB = Path.home() / "apps.json"


def load_apps(path=None):
    db = Path(path) if path else DEFAULT_DB

    if not db.exists():
        raise FileNotFoundError(f"{db} not found.\n" "Run: python -m argus.cli extract")

    try:
        return json.loads(db.read_text())
    except json.JSONDecodeError as e:
        raise RuntimeError(
            f"{db} is not valid JSON.\n"
            "Do not use raw 'pymobiledevice3 apps list' output as apps.json.\n"
            "Regenerate the app database before running analyze/threat/focus."
        ) from e

import json
from pathlib import Path

CREDENTIALS_FILE = Path(__file__).resolve().parent.parent.parent / "device_remote_credentials.json"


def load_credentials_store() -> dict:
    if not CREDENTIALS_FILE.exists():
        return {}
    try:
        with open(CREDENTIALS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_credentials_store(data: dict) -> None:
    try:
        with open(CREDENTIALS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass


def save_device_credentials(
    identifier: str,
    protocol: str,
    username: str,
    password: str | None = None,
    port: int | None = None,
    ssh_key: str | None = None,
) -> None:
    if not identifier:
        return
    data = load_credentials_store()
    key = identifier.strip().lower()
    data[key] = {
        "protocol": protocol,
        "username": username,
        "password": password,
        "port": port,
        "ssh_key": ssh_key,
    }
    save_credentials_store(data)


def get_device_credentials(*identifiers: str | None) -> dict | None:
    """Check for credentials matching any identifier (IP, MAC, or Hostname)."""
    data = load_credentials_store()
    for ident in identifiers:
        if not ident:
            continue
        key = ident.strip().lower()
        if key in data:
            return data[key]
        # Check normalized MAC
        clean_mac = key.replace(":", "").replace("-", "")
        for k, v in data.items():
            if k.replace(":", "").replace("-", "") == clean_mac:
                return v
    return None

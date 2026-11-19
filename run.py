import os
import sys

# Ensure repository root is on sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

try:
    from dotenv import load_dotenv
    env_file = os.path.join(BASE_DIR, ".env")
    if os.path.exists(env_file):
        load_dotenv(env_file)
except ImportError:
    pass

import uvicorn

if __name__ == "__main__":
    port_env = os.environ.get("PORT", "10000").strip()
    try:
        port = int(port_env)
    except (ValueError, TypeError):
        port = 10000

    host = os.environ.get("HOST", "0.0.0.0").strip()
    print(f"[NETOPS] Starting server on {host}:{port}...")
    uvicorn.run("backend.app.main:app", host=host, port=port, workers=1)

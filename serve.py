"""One-command local launcher for the Aegis Sandbox web console.

    python serve.py            # http://127.0.0.1:8000/ui/

Sets dev-friendly defaults (SQLite, local filesystem object store, inline analysis —
no Postgres/Redis/MinIO needed) unless you've already set them in the environment.
For the full prescribed stack instead, use `docker compose up`.
"""

from __future__ import annotations

import os
import sys
import webbrowser
from pathlib import Path
from threading import Timer

ROOT = Path(__file__).parent
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))
os.environ["PYTHONPATH"] = str(SRC) + os.pathsep + os.environ.get("PYTHONPATH", "")

os.environ.setdefault("AEGIS_ENV", "dev")
os.environ.setdefault("DATABASE_URL", f"sqlite+pysqlite:///{ROOT / 'aegis_local.db'}")
os.environ.setdefault("STORAGE_BACKEND", "local")
os.environ.setdefault("LOCAL_STORAGE_DIR", str(ROOT / "data" / "objstore"))
os.environ.setdefault("AEGIS_INLINE_TASKS", "true")

HOST = os.environ.get("AEGIS_API_HOST", "127.0.0.1")
PORT = int(os.environ.get("AEGIS_API_PORT", "8000"))


def main() -> None:
    import uvicorn

    url = f"http://{HOST if HOST != '0.0.0.0' else '127.0.0.1'}:{PORT}/ui/"
    print(f"\n  MalwareTotal console ->  {url}\n")
    if "--no-browser" not in sys.argv:
        Timer(1.2, lambda: webbrowser.open(url)).start()
    uvicorn.run("aegis.api.main:app", host=HOST, port=PORT, reload=False)


if __name__ == "__main__":
    main()

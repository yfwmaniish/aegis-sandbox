"""End-to-end API test: register → login → upload → analyze → fetch results.

Runs fully in-process against SQLite + the local filesystem object store + inline task
execution, so no Postgres/Redis/MinIO are needed. Exercises the whole control-plane
path and the static pipeline together.
"""

from __future__ import annotations

import importlib
import io

import pytest


@pytest.fixture()
def client(tmp_path, monkeypatch):
    # Hermetic config: sqlite file + local object store + inline tasks, all under tmp.
    monkeypatch.setenv("AEGIS_ENV", "test")
    monkeypatch.setenv("DATABASE_URL", f"sqlite+pysqlite:///{tmp_path/'aegis.db'}")
    monkeypatch.setenv("STORAGE_BACKEND", "local")
    monkeypatch.setenv("LOCAL_STORAGE_DIR", str(tmp_path / "objstore"))
    monkeypatch.setenv("AEGIS_INLINE_TASKS", "true")
    monkeypatch.setenv("AEGIS_JWT_SECRET", "test-secret")

    # Rebuild cached singletons/modules that captured settings at import time.
    import aegis.core.config as config

    config.get_settings.cache_clear()
    import aegis.db.base as dbbase

    dbbase.get_engine.cache_clear()
    dbbase.get_sessionmaker.cache_clear()
    import aegis.storage.factory as storage_factory

    storage_factory.get_object_store.cache_clear()

    from fastapi.testclient import TestClient

    main = importlib.import_module("aegis.api.main")
    importlib.reload(main)
    with TestClient(main.app) as c:
        yield c


def _auth_headers(client, username="analyst1", password="supersecret") -> dict:
    # First registration bootstraps an admin; reuse it for all calls.
    client.post("/v1/auth/register", json={"username": username, "password": password})
    resp = client.post("/v1/auth/token", data={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_auth_required(client):
    # No token -> 401 on a protected route.
    r = client.get("/v1/samples/00000000-0000-0000-0000-000000000000")
    assert r.status_code == 401


def test_full_flow_pe(client, minimal_pe):
    headers = _auth_headers(client)

    # Upload sample.
    files = {"file": ("sample.exe", io.BytesIO(minimal_pe), "application/octet-stream")}
    r = client.post("/v1/samples", files=files, headers=headers)
    assert r.status_code == 201, r.text
    sample = r.json()
    assert sample["file_type"] == "pe"
    assert len(sample["sha256"]) == 64

    # Re-upload dedupes by hash (idempotent).
    r2 = client.post("/v1/samples", files={"file": ("again.exe", io.BytesIO(minimal_pe), "x")},
                     headers=headers)
    assert r2.json()["id"] == sample["id"]

    # Create analysis (inline -> runs synchronously).
    r = client.post("/v1/analyses", json={"sample_id": sample["id"], "profile": "static_only"},
                    headers=headers)
    assert r.status_code == 201, r.text
    analysis = r.json()
    assert analysis["state"] == "completed"
    assert analysis["target_os"] == "windows"
    assert analysis["risk_score"] is not None

    aid = analysis["id"]

    # Findings endpoint responds with a valid page (the minimal synthetic PE is clean,
    # so zero findings is expected; detection depth is covered by the analyzer tests).
    r = client.get(f"/v1/analyses/{aid}/findings", headers=headers)
    assert r.status_code == 200
    findings = r.json()
    assert findings["total"] >= 0
    assert all("severity" in f for f in findings["items"])

    # Report blob with the versioned schema.
    r = client.get(f"/v1/analyses/{aid}/report", headers=headers)
    assert r.status_code == 200
    report = r.json()
    assert report["schema_version"]
    assert report["file_type"] == "pe"
    assert report["pe"]["machine"]

    # Timeline shows the lifecycle transitions.
    r = client.get(f"/v1/analyses/{aid}/timeline", headers=headers)
    assert r.status_code == 200
    states = [e["to_state"] for e in r.json()["items"] if e["action"] == "state_transition"]
    assert "completed" in states

    # IOCs endpoint responds (may be empty for a tiny synthetic PE).
    r = client.get(f"/v1/analyses/{aid}/iocs", headers=headers)
    assert r.status_code == 200

    # Threat-intel endpoints: similarity (empty corpus) + generated rules.
    rs = client.get(f"/v1/analyses/{aid}/similar", headers=headers)
    assert rs.status_code == 200
    assert rs.json()["count"] == 0  # only this sample in the corpus

    rr = client.get(f"/v1/analyses/{aid}/rules", headers=headers)
    assert rr.status_code == 200
    rules = rr.json()
    assert rules["yara"]["text"].startswith("rule ")
    assert "detection:" in rules["sigma"]["yaml"]

    # Self-contained HTML report.
    rh = client.get(f"/v1/analyses/{aid}/report.html", headers=headers)
    assert rh.status_code == 200
    assert rh.headers["content-type"].startswith("text/html")
    assert rh.text.startswith("<!doctype html>")
    assert "Analysis Report" in rh.text and "MITRE ATT&CK" in rh.text

    # Corpus scoreboard aggregates the completed analysis.
    cs = client.get("/v1/corpus/scoreboard", headers=headers)
    assert cs.status_code == 200
    board = cs.json()
    assert board["total"] >= 1
    assert board["flagged"] + board["clean"] == board["total"]


def test_rbac_register_after_bootstrap(client):
    # Bootstrap admin.
    _auth_headers(client, "admin1", "adminpassword")
    # Second registration without an admin token must be refused.
    r = client.post("/v1/auth/register", json={"username": "intruder", "password": "password123"})
    assert r.status_code == 403

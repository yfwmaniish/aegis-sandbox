# Aegis Sandbox

AI-assisted, multi-OS **malware static-analysis** platform — the first vertical of the
Aegis Sandbox program (see the source requirements in
[`../AI_Sandbox_Program_Document.md`](../AI_Sandbox_Program_Document.md),
[`../PRD_AI_Sandboxing_Platform.md`](../PRD_AI_Sandboxing_Platform.md),
[`../SRS_AI_Sandboxing_Platform.md`](../SRS_AI_Sandboxing_Platform.md),
[`../TRD_AI_Sandboxing_Platform.md`](../TRD_AI_Sandboxing_Platform.md)).

> ⚠️ **Authorized use only.** This platform is for defensive malware analysis and
> detection engineering on samples you are authorized to handle. Samples are stored as
> bytes in a quarantine object store and are **never executed** by this codebase — the
> dynamic detonation zone is a separate, network-isolated component (not included here).

---

## What's built in this phase

This phase delivers the **static analysis engine** running inside the **full control
plane** prescribed by the TRD, with the dynamic detonation backend left as a clean
plug-in interface (a real KVM/libvirt + Android-emulator backend implements it later).

| Area | Status | Where |
|---|---|---|
| Static engine (PE / ELF / APK) | ✅ deep | [`src/aegis/static/`](src/aegis/static/) |
| Common extractors (hash, entropy, strings, IOCs) | ✅ | [`src/aegis/static/common/`](src/aegis/static/common/) |
| Versioned report schema | ✅ | [`src/aegis/static/models.py`](src/aegis/static/models.py) |
| Analysis state machine + audit | ✅ | [`src/aegis/core/state.py`](src/aegis/core/state.py) |
| Detonation orchestrator interface | ✅ contract | [`src/aegis/orchestrator/`](src/aegis/orchestrator/) |
| Control plane (FastAPI, JWT, RBAC) | ✅ | [`src/aegis/api/`](src/aegis/api/) |
| Celery + Redis task pipeline | ✅ | [`src/aegis/worker/`](src/aegis/worker/) |
| Postgres schema + Alembic | ✅ | [`src/aegis/db/`](src/aegis/db/), [`migrations/`](migrations/) |
| Object storage (S3/MinIO + local) | ✅ | [`src/aegis/storage/`](src/aegis/storage/) |
| Similarity / clustering / YARA-Sigma | 🚧 `501` stubs | intel phase |
| Dynamic detonation backend | 🚧 interface only | detonation zone |

### What the static engine extracts

- **All formats:** SHA256/SHA1/MD5 + TLSH fuzzy hash, whole-file & windowed Shannon
  entropy with a packing verdict, ASCII/UTF-16 strings with tagged "interesting"
  hits, and candidate IOCs (URLs, domains, IPs, emails, hashes, BTC, registry/paths)
  with allow-listing and confidence.
- **PE:** machine/subsystem, sections + per-section entropy & flags, imports +
  **imphash**, exports, resources, Authenticode presence, TLS callbacks, debug PDB
  path. Heuristics: packer sections, RWX sections, high-entropy code, injection/anti-
  debug imports, tiny import tables, stomped timestamps.
- **ELF:** type/arch/endianness, interpreter, sections + entropy, dynamic symbol
  imports, NEEDED libs, RPATH/RUNPATH, text relocations, stripped detection.
  Heuristics: RWX segments, suspicious symbols, rpath hijack risk.
- **APK:** package/SDKs/main activity, permissions partitioned into dangerous/custom,
  components with **effective exported** state + intent actions, signing certs (debug-
  cert flag), native libs, DEX API scan. Heuristics: SMS/OTP capability, accessibility
  abuse, overlay+accessibility banker pattern, device admin, dynamic code loading
  (droppers), excessive permissions.

Every finding is **evidence-first** — it separates *observed facts* from *inference*
(TR-DET-02 / NFR-18) and carries severity + confidence.

---

## Quick start (local, no infra)

Pure-Python parts run on Windows/macOS/Linux with no Docker. (TLSH and the full APK
analyzer need native wheels best provided by the Docker image / Linux.)

```bash
python -m venv .venv && . .venv/Scripts/activate     # or .venv/bin/activate
pip install -e ".[api,worker,dev]"                    # add "static" on Linux for APK/TLSH
pytest -q                                             # run the test suite
```

### Run the API locally (SQLite + filesystem storage + inline tasks)

```bash
export AEGIS_ENV=dev
export DATABASE_URL="sqlite+pysqlite:///./aegis.db"
export STORAGE_BACKEND=local
export AEGIS_INLINE_TASKS=true
uvicorn aegis.api.main:app --reload
# open http://localhost:8000/docs
```

End-to-end with curl:

```bash
# bootstrap admin (first user), then log in
curl -s localhost:8000/v1/auth/register -H 'content-type: application/json' \
     -d '{"username":"analyst","password":"supersecret"}'
TOKEN=$(curl -s localhost:8000/v1/auth/token \
     -d 'username=analyst&password=supersecret' | python -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

# upload a sample, create an analysis, read the report
SAMPLE=$(curl -s localhost:8000/v1/samples -H "authorization: Bearer $TOKEN" -F file=@/path/to/sample.exe)
SID=$(echo "$SAMPLE" | python -c 'import sys,json;print(json.load(sys.stdin)["id"])')
AID=$(curl -s localhost:8000/v1/analyses -H "authorization: Bearer $TOKEN" \
     -H 'content-type: application/json' -d "{\"sample_id\":\"$SID\"}" \
     | python -c 'import sys,json;print(json.load(sys.stdin)["id"])')
curl -s localhost:8000/v1/analyses/$AID/report -H "authorization: Bearer $TOKEN"
```

### Analyze a file straight from the CLI

```bash
python -m aegis.cli analyze /path/to/sample.exe          # pretty summary
python -m aegis.cli analyze /path/to/app.apk --json      # full JSON report
```

---

## Full stack (Docker Compose)

Brings up the whole control-plane data plane (Postgres, Redis, MinIO, OpenSearch,
Qdrant) plus the API and a Celery worker, with Alembic migrations applied on start.

```bash
docker compose up --build
# API:        http://localhost:8000/docs
# MinIO:      http://localhost:9001  (aegis / aegis-secret)
# OpenSearch: http://localhost:9200
```

The **detonation zone is intentionally absent** — it is network-isolated (TRD §4) and
implements [`SandboxOrchestrator`](src/aegis/orchestrator/base.py) separately.

---

## API surface (`/v1`)

| Method | Path | Notes |
|---|---|---|
| `POST` | `/v1/auth/register` | bootstrap admin, then admin-only |
| `POST` | `/v1/auth/token` | OAuth2 password → JWT |
| `POST` | `/v1/samples` | upload; SHA256 dedupe; quarantine store |
| `GET`  | `/v1/samples/{id}` | |
| `POST` | `/v1/analyses` | create + dispatch (inline/Celery) |
| `GET`  | `/v1/analyses/{id}` | lifecycle state + risk score |
| `GET`  | `/v1/analyses/{id}/findings` | paginated, severity filter |
| `GET`  | `/v1/analyses/{id}/iocs` | paginated, type filter |
| `GET`  | `/v1/analyses/{id}/report` | full versioned static report |
| `GET`  | `/v1/analyses/{id}/timeline` | hash-chained audit / state transitions |
| `GET`  | `/v1/analyses/{id}/similar` | `501` (intel phase) |
| `GET`  | `/v1/analyses/{id}/rules` | `501` (intel phase) |

---

## Architecture

```
            ┌──────────────┐   POST /v1/samples,/analyses    ┌──────────────┐
   analyst ─┤ FastAPI (api)├────────────────────────────────┤ Postgres     │
            └──────┬───────┘   JWT + RBAC, state machine     │ (metadata)   │
                   │ enqueue                                  └──────────────┘
                   ▼                                          ┌──────────────┐
            ┌──────────────┐   StaticReport → findings/IOCs   │ MinIO / S3   │
            │ Celery worker├──────────────────────────────────┤ (quarantine) │
            └──────┬───────┘                                  └──────────────┘
                   │ analyze_bytes()
                   ▼
            ┌──────────────────────────────────────────┐
            │ Static engine: dispatch → PE / ELF / APK  │
            │ + hash / entropy / strings / IOC / rules  │
            └──────────────────────────────────────────┘

   (future)  Orchestrator interface ─▶ Detonation zone: KVM VMs / Android emulators
```

Analysis lifecycle (SRS §7): `created → queued → [provisioning → running →
collecting →] processing → reporting → completed`, with `failed_*` / `terminated_policy`
exits. Static-only runs take the `queued → processing` fast path. Every transition is
written to a tamper-evident, hash-chained audit log.

---

## Development

```bash
pytest -q            # tests (engine, state machine, router, API e2e)
ruff check src tests # lint
mypy src             # types
alembic revision --autogenerate -m "msg"   # new migration
alembic upgrade head                        # apply
```

### Layout

```
src/aegis/
  static/        # the static analysis engine (PE/ELF/APK + common extractors)
  core/          # config, enums, state machine
  orchestrator/  # detonation interface + environment router (no hypervisor binding)
  db/            # SQLAlchemy models, persistence helpers, audit chaining
  storage/       # object store abstraction (S3/MinIO + local)
  api/           # FastAPI app, auth, routers, schemas
  worker/        # Celery app + the static pipeline
migrations/      # Alembic
tests/           # hermetic tests with synthetic PE/ELF/APK fixtures
```
```

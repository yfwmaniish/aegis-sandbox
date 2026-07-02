# Aegis Sandbox

[![CI](https://github.com/yfwmaniish/aegis-sandbox/actions/workflows/ci.yml/badge.svg)](https://github.com/yfwmaniish/aegis-sandbox/actions/workflows/ci.yml)

**▶ Demo walkthrough + pitch: [`DEMO.md`](DEMO.md)**

AI-assisted, multi-OS **malware analysis** platform — static engine, **real isolated
detonation** (Android + Linux), an LLM understanding layer, visualizations, threat-intel
generation, a VirusTotal comparison, exportable reports and a corpus catch-rate
scoreboard, behind a FastAPI control plane and a web console. Built to the Aegis Sandbox
program spec (see
[`../AI_Sandbox_Program_Document.md`](../AI_Sandbox_Program_Document.md),
[`../PRD_AI_Sandboxing_Platform.md`](../PRD_AI_Sandboxing_Platform.md),
[`../SRS_AI_Sandboxing_Platform.md`](../SRS_AI_Sandboxing_Platform.md),
[`../TRD_AI_Sandboxing_Platform.md`](../TRD_AI_Sandboxing_Platform.md)).

> ⚠️ **Authorized use only.** For defensive malware analysis on samples you are
> authorized to handle. Static analysis is **parse-only** — the sample is never executed.
> Dynamic detonation runs the sample **only inside a disposable, network-isolated guest**
> (Android emulator in airplane mode, or a Docker container with `--network none`), which
> is verified offline before staging and torn down after — the host is never touched, and
> live malware never runs on it. Live secrets/samples stay in git-ignored files.

---

## What's built

The static engine runs inside the **full control plane** prescribed by the TRD, and the
detonation, intelligence and reporting layers plug into it through clean interfaces.

| Area | Status | Where |
|---|---|---|
| Static engine (PE / ELF / APK / archive) | ✅ deep | [`src/aegis/static/`](src/aegis/static/) |
| Common extractors (hash, entropy, strings, IOCs) | ✅ | [`src/aegis/static/common/`](src/aegis/static/common/) |
| Versioned report schema + evidence-first findings | ✅ | [`src/aegis/static/models.py`](src/aegis/static/models.py) |
| Analysis state machine + hash-chained audit | ✅ | [`src/aegis/core/state.py`](src/aegis/core/state.py) |
| Control plane (FastAPI, JWT, RBAC) + web console | ✅ | [`src/aegis/api/`](src/aegis/api/) |
| Celery + Redis pipeline (inline mode for local) | ✅ | [`src/aegis/worker/`](src/aegis/worker/) |
| Postgres schema + Alembic / SQLite (local) | ✅ | [`src/aegis/db/`](src/aegis/db/), [`migrations/`](migrations/) |
| Object storage (S3/MinIO + local) | ✅ | [`src/aegis/storage/`](src/aegis/storage/) |
| **Dynamic detonation — Android (AVD/Genymotion)** | ✅ real, isolated | [`dynamic/`](src/aegis/dynamic/), [`orchestrator/avd.py`](src/aegis/orchestrator/avd.py) |
| **Dynamic detonation — Linux/ELF (Docker + strace)** | ✅ real, isolated | [`orchestrator/docker_linux.py`](src/aegis/orchestrator/docker_linux.py) |
| **Dynamic detonation — Windows/PE** | ✅ honest scaffold (needs a VM) | [`orchestrator/windows.py`](src/aegis/orchestrator/windows.py) |
| **LLM understanding (Claude)** | ✅ | [`src/aegis/ai/`](src/aegis/ai/) · `ANTHROPIC_API_KEY` |
| **Visualizations (radar / heatmap / ATT&CK / graph)** | ✅ deterministic | [`src/aegis/insights/`](src/aegis/insights/) |
| **Threat intel — similarity + YARA/Sigma** | ✅ | [`src/aegis/intel/`](src/aegis/intel/) |
| **VirusTotal comparison (hash-only)** | ✅ | [`src/aegis/intel/virustotal.py`](src/aegis/intel/virustotal.py) · `VIRUSTOTAL_API_KEY` |
| **Self-contained HTML/PDF report** | ✅ | [`src/aegis/report/`](src/aegis/report/) |
| **Corpus catch-rate scoreboard** | ✅ | [`src/aegis/corpus/`](src/aegis/corpus/) |

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
- **Office maldocs (.doc/.xls/.docx/.xlsm):** OLE + OOXML macro detection (olevba when
  installed, byte-scan fallback), auto-exec triggers (AutoOpen/Document_Open/…), shell/
  download primitives, remote template injection, DDE. The #1 delivery vector.
- **PDF:** structure + dangerous-feature scan (deobfuscating `#XX` names): `/JavaScript`,
  `/OpenAction`, `/AA`, `/Launch`, `/EmbeddedFile`, `/RichMedia`, `/JBIG2Decode`, encryption.
- **Scripts (JS/VBScript/PowerShell/batch/HTA/WSF):** language detection, obfuscation
  scoring (base64/hex blobs, char-code assembly, encoded commands), suspicious APIs, and
  the download-and-execute stager pattern.
- **Mach-O (macOS, thin + universal):** architectures, file type, linked dylibs, @rpath,
  code-signature and segment-encryption presence.
- **Delivery/initial-access formats:** **.lnk** (Shell Link parse → command-line args,
  living-off-the-land interpreters), **RTF** (embedded OLE, Equation Editor exploit,
  hex-encoded PE), **HTML smuggling** (encoded blob + in-browser blob/download
  reconstruction), **JAR** (Main-Class + Runtime.exec/URLClassLoader), and **ISO/IMG**
  (Mark-of-the-Web-bypass container carrying .lnk/.exe lures).

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

### Web console — one command

```bash
python serve.py            # -> http://127.0.0.1:8000/ui/
```

`serve.py` sets dev-friendly defaults (SQLite, local object store, inline analysis — no
Postgres/Redis/MinIO needed). The console: sign in (first account becomes admin), upload
a sample, pick **Static only** or **Dynamic (detonate)**, and get the verdict, findings,
IOCs, the **Visual analysis** panels, **Threat intelligence** (similar samples + YARA/Sigma),
and buttons for **✨ Explain with AI**, **⬇ Export report**, and **🔍 Compare with
VirusTotal**. The **📊 Corpus** button shows the catch-rate scoreboard across all samples.

Optional keys go in a git-ignored `.env` (never committed): `ANTHROPIC_API_KEY` (AI
narrative), `VIRUSTOTAL_API_KEY` (VT comparison — only the SHA-256 is ever sent).

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

### CLI

```bash
python -m aegis.cli analyze /path/to/sample.exe          # pretty summary
python -m aegis.cli analyze /path/to/app.apk --json      # full JSON report
python -m aegis.cli scan   /path/to/folder               # batch catch-rate scoreboard
python -m aegis.cli scan   /path/to/folder --virustotal  # + "caught by Aegis, missed by VT"
python -m aegis.cli doctor                               # detonation toolchain preflight
```

---

## Dynamic analysis (detonation)

Runs an APK in an **Android emulator**, observes what it actually does (runtime
permissions, network/C2, SMS, location, mic/camera, command exec, dynamic code
loading), then **uninstalls + reverts the snapshot** — nothing persists, the host is
never touched. The behaviour is normalized into a canonical event stream
([TRD §6.2](src/aegis/dynamic/models.py)) and scored by the dynamic detectors.

Architecture: the analytical core ([`aegis.dynamic`](src/aegis/dynamic/)) is
infra-agnostic and fully tested with fixtures + a fake backend; the real device is
driven by a pluggable [`SandboxOrchestrator`](src/aegis/orchestrator/base.py) backend.

### Try it now (no device — fake backend)

```bash
export SANDBOX_BACKEND=fake          # replays a canned spyware run through the pipeline
# create an analysis with a non-static profile -> POST /v1/analyses {"profile":"standard"}
# then GET /v1/analyses/{id}/dynamic   and   /findings
```

### Real detonation — `avd` backend (free, recommended)

The Android Emulator path needs no license and runs on Hyper-V (WHPX). It also isolates
cleanly: adb runs on a separate channel from the guest network, so the engine enforces
**airplane mode** and **verifies no internet egress before staging the sample** — aborting
the run if the device can still reach the internet (`DYNAMIC_REQUIRE_ISOLATION=true`).

```bash
python -m aegis.cli doctor            # checks emulator / adb / frida per backend
```

Install:
1. **Android SDK** `emulator` + `platform-tools` (`adb`) on PATH (Android Studio or
   command-line tools). Set `ANDROID_SDK_ROOT` if not on PATH.
2. Create an AVD (x86_64, API 30, Google APIs) named **`aegis-avd`** (or set `AVD_NAME`).
3. `pip install frida frida-tools` and provide a matching frida-server via `FRIDA_SERVER_PATH`.

```bash
export SANDBOX_BACKEND=avd
export AVD_NAME=aegis-avd
export FRIDA_SERVER_PATH=/path/to/frida-server-<ver>-android-x86_64
```

### Real detonation — `docker` backend (Linux / ELF)

Detonates an ELF inside a **locked-down disposable container** and records real syscall
behaviour with `strace`: `--network none` (no egress — the isolation invariant),
read-only rootfs, tmpfs scratch, all caps dropped except the one `strace` needs
(`SYS_PTRACE`), `no-new-privileges`, and pid/memory/CPU caps plus a wall-clock timeout.
`execve`/`connect`/file-write/spawn syscalls normalize into the same event stream and
feed the same detectors. One-time image build needs internet; detonations are offline.

```bash
# start Docker Desktop / Engine (Linux containers), then:
export SANDBOX_BACKEND=docker      # first run builds aegis-linux-sandbox:latest (~1 min)
# submit an ELF with profile "standard"
```

**Live network-capture ("sinkhole") mode** — `DOCKER_SINKHOLE=true` detonates the sample
on a Docker `--internal` network (no route off the host) alongside a DNS/HTTP sinkhole
that answers every query and logs it. The sample **attempts** its C2, and every domain/URL
it reaches for is captured (`dyn.c2_beacon`, folded into peers + the behaviour graph +
ATT&CK) — while nothing ever leaves the machine. Default off (pure air-gap `--network none`).

### Real detonation — `genymotion` (APK) / `windows` (PE)

`genymotion`: same Android flow via `gmtool` + `adb` + Frida (`gmtool` may need a **paid**
license). `windows`: integrates an external, isolated Windows guest + in-guest agent
(`WINDOWS_VM_NAME` + `WINDOWS_AGENT_URL`) and **refuses to run** when unconfigured rather
than emitting fabricated telemetry.

Routing is by file type: **APK → `avd`/`genymotion`, ELF → `docker`, PE → `windows`**.
Analyses with profile `standard`/`hardened` detonate; runtime findings merge into the same
`/findings` + risk score, and the full event stream is at `GET /v1/analyses/{id}/dynamic`.

## Understanding, visualizations & intel

Every completed analysis can be enriched — all deterministic and offline **except** the
two that call out (clearly gated on their own API keys):

- **Visual analysis** ([`insights/`](src/aegis/insights/)) — a capability radar, an
  Android permission heatmap, a **MITRE ATT&CK** matrix (indicator → technique), and a
  behaviour/network graph, derived from the static (+ dynamic) report. No key required.
- **Threat intel** ([`intel/`](src/aegis/intel/)) — **similarity** ranking against the
  corpus (shared indicators/endpoints, package/imphash, TLSH), and generated **YARA +
  Sigma** rules tagged with the mapped ATT&CK techniques.
- **VirusTotal comparison** — hash-only lookup that puts VT's multi-engine verdict next
  to Aegis's, with an explicit **detection-gap** flag for "Aegis caught it, VT missed it."
- **AI narrative** ([`ai/`](src/aegis/ai/)) — a Claude-written summary, behaviour
  workflow, ATT&CK mapping and defensive actions (human-review-required).
- **Report export** ([`report/`](src/aegis/report/)) — a single self-contained HTML file
  (inline SVG, no JS) bundling all of the above; open it and Print → Save as PDF.
- **Corpus scoreboard** ([`corpus/`](src/aegis/corpus/)) — batch metrics across all
  samples: flagged-vs-clean catch rate, risk distribution, top capabilities, and the
  count Aegis flagged that VirusTotal did not.

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
| `GET`  | `/v1/analyses/{id}/dynamic` | detonation event stream + behaviour roll-ups |
| `GET`  | `/v1/analyses/{id}/timeline` | hash-chained audit / state transitions |
| `GET`  | `/v1/analyses/{id}/visualizations` | radar / heatmap / ATT&CK / graph (deterministic) |
| `GET`  | `/v1/analyses/{id}/similar` | sample similarity ranking |
| `GET`  | `/v1/analyses/{id}/rules` | generated YARA + Sigma |
| `GET`  | `/v1/analyses/{id}/virustotal` | VT-vs-Aegis comparison (hash-only) |
| `GET`  | `/v1/analyses/{id}/report.html` | self-contained HTML/PDF report |
| `POST` | `/v1/analyses/{id}/understanding` | generate Claude narrative (`GET` to fetch) |
| `GET`  | `/v1/corpus/scoreboard` | catch-rate scoreboard across all samples |
| `GET`  | `/ui/` | web console |

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

   detonate  Orchestrator ─▶ isolated guest: Android emulator (airplane) / Docker (--network none)
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
  static/        # the static analysis engine (PE/ELF/APK/archive + common extractors)
  dynamic/       # canonical event schema, normalizers (frida/logcat/strace), detectors
  orchestrator/  # detonation backends: avd, docker_linux, genymotion, windows, fake + router
  ai/            # Claude understanding layer (graceful no-key fallback)
  insights/      # deterministic visualizations (radar/heatmap/ATT&CK/graph)
  intel/         # similarity, YARA/Sigma generation, VirusTotal comparison
  report/        # self-contained HTML/PDF report builder
  corpus/        # batch scan + catch-rate scoreboard
  core/          # config, enums, state machine
  db/            # SQLAlchemy models, persistence helpers, audit chaining
  storage/       # object store abstraction (S3/MinIO + local)
  api/           # FastAPI app, auth, routers, schemas, web console (static/)
  worker/        # Celery app + the static/dynamic pipeline
serve.py         # one-command local launcher for the web console
migrations/      # Alembic
tests/           # hermetic tests (111) with synthetic PE/ELF/APK fixtures
```
```

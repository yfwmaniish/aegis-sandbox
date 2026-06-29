"""Genymotion detonation backend (Android) implementing :class:`SandboxOrchestrator`.

Drives a Genymotion Desktop device via ``gmtool`` + ``adb`` and instruments the target
with Frida. One run: factory-reset a clean device → install the APK → spawn it under
Frida + drive interaction with monkey → collect Frida JSONL / logcat / dumpsys → upload
artifacts → uninstall + reset (snapshot rollback). Nothing persists; the host is never
touched.

This backend shells out to external tools that must be installed (see ``preflight``).
Where those tools are absent it fails cleanly so the control plane can report a precise
setup error rather than crashing.
"""

from __future__ import annotations

import tempfile
import time
import uuid
from pathlib import Path

from aegis.core.enums import TargetOS
from aegis.orchestrator.base import (
    DetonationResult,
    EnvironmentSpec,
    ExecutionBudget,
    RollbackResult,
    SandboxOrchestrator,
    SandboxSession,
    register_backend,
)
from aegis.orchestrator.shell import have, run

REQUIRED_TOOLS = ("gmtool", "adb")
OPTIONAL_TOOLS = ("frida",)  # frida is a Python package + on-device server

_HOOKS_JS = Path(__file__).resolve().parent.parent / "dynamic" / "agent" / "hooks.js"


class GenymotionUnavailable(RuntimeError):
    """Raised when required Genymotion/adb tooling is not installed."""


class GenymotionOrchestrator(SandboxOrchestrator):
    supported_os = frozenset({TargetOS.ANDROID})

    def __init__(self, settings=None, store=None, device_name: str | None = None):
        self.settings = settings
        self.store = store
        self.device_name = device_name or getattr(settings, "genymotion_device", None) or "aegis-android"

    # ── preflight ────────────────────────────────────────────────────────────
    @staticmethod
    def preflight() -> dict[str, bool]:
        """Report which tools are present (for the doctor command)."""
        status = {t: have(t) for t in REQUIRED_TOOLS}
        try:
            import frida  # noqa: F401
            status["frida(python)"] = True
        except ImportError:
            status["frida(python)"] = False
        return status

    def _require_tools(self) -> None:
        missing = [t for t in REQUIRED_TOOLS if not have(t)]
        if missing:
            raise GenymotionUnavailable(
                f"missing required tools: {', '.join(missing)}. "
                "Install Genymotion Desktop (gmtool) and Android platform-tools (adb)."
            )

    # ── lifecycle ──────────────────────────────────────────────────────────────
    def provision(self, analysis_id: str, spec: EnvironmentSpec) -> SandboxSession:
        self._require_tools()
        name = spec.image or self.device_name
        # Clean baseline, then boot.
        run(["gmtool", "admin", "factoryreset", name], timeout=120)
        started = run(["gmtool", "admin", "start", name], timeout=300)
        if not started.ok:
            raise GenymotionUnavailable(f"failed to start device '{name}': {started.stderr.strip()}")
        serial = self._adb_serial(name)
        if serial:
            run(["adb", "-s", serial, "wait-for-device"], timeout=120)
        return SandboxSession(
            session_id=f"gm-{uuid.uuid4().hex[:12]}",
            analysis_id=analysis_id,
            spec=spec,
            snapshot_id=name,
            extra={"device_name": name, "serial": serial or ""},
        )

    def stage_sample(self, session: SandboxSession, sample_ref: str) -> None:
        serial = session.extra.get("serial")
        data = self._fetch_sample(sample_ref)
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp:
            tmp.write(data)
            apk_path = tmp.name
        session.extra["package"] = self._package_name(data) or ""
        res = run(["adb", "-s", serial, "install", "-r", "-g", apk_path], timeout=300)
        Path(apk_path).unlink(missing_ok=True)
        if not res.ok and "Success" not in res.stdout:
            session.extra["install_error"] = (res.stderr or res.stdout).strip()[:500]

    def execute(self, session: SandboxSession, budget: ExecutionBudget) -> DetonationResult:
        serial = session.extra.get("serial")
        package = session.extra.get("package") or ""
        start = time.time()
        if session.extra.get("install_error") or not package:
            return DetonationResult(
                session_id=session.session_id, analysis_id=session.analysis_id,
                completed=False, runtime_seconds=0.0, exit_reason="install_failed",
            )

        frida_events = self._run_with_frida(serial, package, budget.max_runtime_seconds)
        # Drive UI to trigger behaviour (best-effort; non-fatal).
        run(["adb", "-s", serial, "shell", "monkey", "-p", package,
             "--throttle", "300", "-v", "400"], timeout=budget.max_runtime_seconds + 30)

        session.extra["frida_jsonl"] = frida_events
        return DetonationResult(
            session_id=session.session_id, analysis_id=session.analysis_id,
            completed=True, runtime_seconds=round(time.time() - start, 2),
            exit_reason="finished",
        )

    def collect(self, session: SandboxSession) -> DetonationResult:
        serial = session.extra.get("serial")
        package = session.extra.get("package") or ""
        logcat = run(["adb", "-s", serial, "logcat", "-d", "-v", "threadtime"], timeout=120).stdout
        dumpsys = run(["adb", "-s", serial, "shell", "dumpsys", "package", package], timeout=120).stdout
        frida_jsonl = session.extra.get("frida_jsonl", "")

        refs = []
        refs.append(self._upload(session, "frida.jsonl", frida_jsonl))
        refs.append(self._upload(session, "logcat.txt", logcat))
        refs.append(self._upload(session, "dumpsys.txt", dumpsys))
        return DetonationResult(
            session_id=session.session_id, analysis_id=session.analysis_id,
            completed=True, runtime_seconds=0.0, exit_reason="collected",
            raw_refs=[r for r in refs if r], artifact_refs=[r for r in refs if r],
        )

    def teardown(self, session: SandboxSession) -> RollbackResult:
        serial = session.extra.get("serial")
        package = session.extra.get("package")
        name = session.extra.get("device_name", self.device_name)
        if serial and package:
            run(["adb", "-s", serial, "uninstall", package], timeout=60)
        run(["gmtool", "admin", "stop", name], timeout=120)
        reset = run(["gmtool", "admin", "factoryreset", name], timeout=120)
        return RollbackResult(
            session_id=session.session_id,
            rolled_back=reset.ok, verified=reset.ok,
            detail="factory reset" if reset.ok else reset.stderr.strip()[:200],
        )

    def reap_orphans(self, older_than_seconds: int) -> list[str]:
        listed = run(["gmtool", "admin", "list", "--running"], timeout=60)
        reaped: list[str] = []
        for line in listed.stdout.splitlines():
            if self.device_name in line:
                run(["gmtool", "admin", "stop", self.device_name], timeout=120)
                reaped.append(self.device_name)
        return reaped

    # ── helpers ────────────────────────────────────────────────────────────────
    def _adb_serial(self, device_name: str) -> str | None:
        details = run(["gmtool", "admin", "details", device_name], timeout=30)
        for line in details.stdout.splitlines():
            low = line.lower()
            if ("ip" in low or "adb" in low) and ":" in line:
                token = line.split(":", 1)[1].strip().split()[0]
                if token.count(".") == 3 or ":" in token:
                    return token if ":" in token else f"{token}:5555"
        # Fallback: first attached device.
        devs = run(["adb", "devices"], timeout=30)
        for line in devs.stdout.splitlines()[1:]:
            if "\tdevice" in line:
                return line.split("\t")[0]
        return None

    def _run_with_frida(self, serial: str | None, package: str, seconds: int) -> str:
        """Spawn the app under Frida, collect send() events for ``seconds``, return JSONL."""
        try:
            import frida  # lazy optional dep
        except ImportError:
            return ""
        import json as _json

        events: list[str] = []
        try:
            device = frida.get_device(serial) if serial else frida.get_usb_device(timeout=10)
            pid = device.spawn([package])
            sess = device.attach(pid)
            script = sess.create_script(_HOOKS_JS.read_text(encoding="utf-8"))

            def on_message(message, _data):
                if message.get("type") == "send":
                    events.append(_json.dumps(message.get("payload", {})))

            script.on("message", on_message)
            script.load()
            device.resume(pid)
            time.sleep(seconds)
            with _suppress():
                sess.detach()
        except Exception as exc:  # noqa: BLE001 - frida failure shouldn't abort the run
            events.append(_json.dumps({"t": "log", "api": "frida.error", "value": str(exc)}))
        return "\n".join(events)

    def _fetch_sample(self, sample_ref: str) -> bytes:
        # sample_ref is "s3://bucket/key"; read via the injected object store.
        if self.store is None:
            raise GenymotionUnavailable("no object store configured for sample staging")
        _, _, rest = sample_ref.partition("://")
        bucket, _, key = rest.partition("/")
        return self.store.get(bucket, key)

    def _package_name(self, data: bytes) -> str | None:
        try:
            from aegis.static.apk import _import_apk_class

            return _import_apk_class()(data, raw=True).get_package()
        except Exception:  # noqa: BLE001
            return None

    def _upload(self, session: SandboxSession, name: str, text: str) -> str | None:
        if self.store is None or not text:
            return None
        bucket = getattr(self.settings, "s3_bucket_artifacts", "aegis-artifacts")
        key = f"{session.analysis_id}/dynamic/{name}"
        return self.store.put(bucket, key, text.encode("utf-8", "replace"), content_type="text/plain")


class _suppress:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return True


register_backend("genymotion", GenymotionOrchestrator)

"""Android Emulator (AVD) detonation backend — the free, no-license path.

Drives the official Android SDK emulator via ``emulator`` + ``adb`` + Frida. One run:
boot a clean AVD (``-wipe-data``) → **enforce + verify network isolation** → install the
APK → spawn under Frida + drive with monkey → collect Frida JSONL / logcat / dumpsys →
uninstall + kill the emulator. No host-only switch needed: the emulator's adb runs on a
separate channel from the guest network, so airplane mode isolates the sample while adb
stays alive.

Requires the Android SDK emulator + platform-tools on PATH (or ``ANDROID_SDK_ROOT``), an
AVD named per ``AVD_NAME``, and (for API hooking) ``pip install frida`` + a matching
frida-server pushed to the device (``FRIDA_SERVER_PATH``). Missing Frida degrades to
logcat + permissions only rather than failing.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import subprocess
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
from aegis.orchestrator.isolation import assert_isolated
from aegis.orchestrator.shell import have, run

REQUIRED_TOOLS = ("emulator", "adb")
_HOOKS_JS = Path(__file__).resolve().parent.parent / "dynamic" / "agent" / "hooks.js"
_DEFAULT_PORT = 5554


class AvdUnavailable(RuntimeError):
    """Raised when the Android SDK emulator / adb tooling is not available."""


class AvdOrchestrator(SandboxOrchestrator):
    supported_os = frozenset({TargetOS.ANDROID})

    def __init__(self, settings=None, store=None):
        self.settings = settings
        self.store = store
        self.avd_name = getattr(settings, "avd_name", None) or "aegis-avd"
        self._sdk_root = getattr(settings, "android_sdk_root", None)

    # ── preflight ──────────────────────────────────────────────────────────────
    @staticmethod
    def preflight() -> dict[str, bool]:
        status = {t: have(t) for t in REQUIRED_TOOLS}
        try:
            import frida  # noqa: F401
            status["frida(python)"] = True
        except ImportError:
            status["frida(python)"] = False
        return status

    def _bin(self, name: str) -> str:
        """Resolve a tool from PATH, falling back to the ANDROID_SDK_ROOT layout.

        The detonation runs in the server process, whose PATH may predate the SDK
        install — so we resolve via ANDROID_SDK_ROOT too. On Windows the executables
        carry a ``.exe`` suffix."""
        found = shutil.which(name)
        if found:
            return found
        if self._sdk_root:
            sub = {"emulator": "emulator", "adb": "platform-tools"}.get(name, "")
            exe = name + (".exe" if os.name == "nt" else "")
            cand = Path(self._sdk_root) / sub / exe
            if cand.exists():
                return str(cand)
        return name  # let it fail with a clear error if truly missing

    # ── lifecycle ──────────────────────────────────────────────────────────────
    def _have(self, name: str) -> bool:
        """True if the tool resolves via PATH or ANDROID_SDK_ROOT (not just PATH)."""
        return Path(self._bin(name)).exists()

    def provision(self, analysis_id: str, spec: EnvironmentSpec) -> SandboxSession:
        for tool in ("adb", "emulator"):
            if not self._have(tool):
                raise AvdUnavailable(
                    f"{tool} not found on PATH or under ANDROID_SDK_ROOT "
                    f"({self._sdk_root or 'unset'}). Install Android platform-tools/emulator."
                )
        name = spec.image or self.avd_name
        serial = f"emulator-{_DEFAULT_PORT}"

        # Boot a clean AVD (wipe user data each run = our snapshot-rollback equivalent).
        subprocess.Popen(
            [self._bin("emulator"), "-avd", name, "-port", str(_DEFAULT_PORT),
             "-no-window", "-no-audio", "-no-boot-anim", "-no-snapshot", "-wipe-data",
             "-netdelay", "none", "-netspeed", "full"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        if not self._wait_boot(serial, 300):
            self._kill(serial)
            raise AvdUnavailable(f"AVD '{name}' did not finish booting in time")

        # Root for Frida (works on AOSP / google_apis images, not playstore images).
        run([self._bin("adb"), "-s", serial, "root"], timeout=30)
        run([self._bin("adb"), "-s", serial, "wait-for-device"], timeout=60)
        self._start_frida_server(serial)

        # ── ISOLATION GATE: enforce airplane mode, verify no egress, abort if reachable ──
        require = getattr(self.settings, "dynamic_require_isolation", True)
        try:
            isolated = assert_isolated(serial, require=require)
        except Exception:
            self._kill(serial)
            raise

        return SandboxSession(
            session_id=f"avd-{uuid.uuid4().hex[:12]}",
            analysis_id=analysis_id, spec=spec, snapshot_id=name,
            extra={"serial": serial, "device_name": name, "isolated": str(isolated)},
        )

    def stage_sample(self, session: SandboxSession, sample_ref: str) -> None:
        serial = session.extra.get("serial")
        data = self._fetch_sample(sample_ref)
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp:
            tmp.write(data)
            apk_path = tmp.name
        session.extra["package"] = self._package_name(data) or ""
        res = run([self._bin("adb"), "-s", serial, "install", "-r", "-g", apk_path], timeout=300)
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
        session.extra["frida_jsonl"] = self._run_with_frida(serial, package, budget.max_runtime_seconds)
        run([self._bin("adb"), "-s", serial, "shell", "monkey", "-p", package,
             "--throttle", "300", "-v", "400"], timeout=budget.max_runtime_seconds + 30)
        return DetonationResult(
            session_id=session.session_id, analysis_id=session.analysis_id,
            completed=True, runtime_seconds=round(time.time() - start, 2), exit_reason="finished",
        )

    def collect(self, session: SandboxSession) -> DetonationResult:
        serial = session.extra.get("serial")
        package = session.extra.get("package") or ""
        logcat = run([self._bin("adb"), "-s", serial, "logcat", "-d", "-v", "threadtime"], timeout=120).stdout
        dumpsys = run([self._bin("adb"), "-s", serial, "shell", "dumpsys", "package", package], timeout=120).stdout
        refs = [
            self._upload(session, "frida.jsonl", session.extra.get("frida_jsonl", "")),
            self._upload(session, "logcat.txt", logcat),
            self._upload(session, "dumpsys.txt", dumpsys),
        ]
        return DetonationResult(
            session_id=session.session_id, analysis_id=session.analysis_id,
            completed=True, runtime_seconds=0.0, exit_reason="collected",
            raw_refs=[r for r in refs if r], artifact_refs=[r for r in refs if r],
        )

    def teardown(self, session: SandboxSession) -> RollbackResult:
        serial = session.extra.get("serial")
        package = session.extra.get("package")
        if serial and package:
            run([self._bin("adb"), "-s", serial, "uninstall", package], timeout=60)
        killed = self._kill(serial)
        return RollbackResult(
            session_id=session.session_id, rolled_back=killed, verified=killed,
            detail="emulator killed + data wiped on next boot" if killed else "kill failed",
        )

    def reap_orphans(self, older_than_seconds: int) -> list[str]:
        devs = run([self._bin("adb"), "devices"], timeout=30)
        reaped: list[str] = []
        for line in devs.stdout.splitlines()[1:]:
            if line.startswith("emulator-") and "\tdevice" in line:
                serial = line.split("\t")[0]
                if self._kill(serial):
                    reaped.append(serial)
        return reaped

    # ── helpers ──────────────────────────────────────────────────────────────
    def _wait_boot(self, serial: str, timeout: int) -> bool:
        run([self._bin("adb"), "-s", serial, "wait-for-device"], timeout=timeout)
        deadline = time.time() + timeout
        while time.time() < deadline:
            r = run([self._bin("adb"), "-s", serial, "shell", "getprop", "sys.boot_completed"], timeout=10)
            if r.stdout.strip() == "1":
                return True
            time.sleep(2)
        return False

    def _kill(self, serial: str | None) -> bool:
        if not serial:
            return False
        return run([self._bin("adb"), "-s", serial, "emu", "kill"], timeout=30).ok

    def _start_frida_server(self, serial: str) -> None:
        path = getattr(self.settings, "frida_server_path", None)
        if not path or not Path(path).exists():
            return
        adb = self._bin("adb")
        run([adb, "-s", serial, "push", path, "/data/local/tmp/frida-server"], timeout=120)
        run([adb, "-s", serial, "shell", "chmod", "755", "/data/local/tmp/frida-server"], timeout=15)
        # Detached so it keeps running for the spawn below.
        subprocess.Popen(
            [adb, "-s", serial, "shell", "su", "-c", "/data/local/tmp/frida-server"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(2)

    def _run_with_frida(self, serial: str | None, package: str, seconds: int) -> str:
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
            script.on("message", lambda m, _d: events.append(_json.dumps(m.get("payload", {})))
                      if m.get("type") == "send" else None)
            script.load()
            device.resume(pid)
            time.sleep(seconds)
            with contextlib.suppress(Exception):
                sess.detach()
        except Exception as exc:  # noqa: BLE001 - frida failure must not abort the run
            events.append(_json.dumps({"t": "log", "api": "frida.error", "value": str(exc)}))
        return "\n".join(events)

    def _fetch_sample(self, sample_ref: str) -> bytes:
        if self.store is None:
            raise AvdUnavailable("no object store configured for sample staging")
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
        return self.store.put(bucket, f"{session.analysis_id}/dynamic/{name}",
                              text.encode("utf-8", "replace"), content_type="text/plain")


register_backend("avd", AvdOrchestrator)

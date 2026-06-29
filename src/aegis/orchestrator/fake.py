"""In-memory fake detonation backend for tests and demos.

Implements the full :class:`SandboxOrchestrator` lifecycle but, instead of booting a
device, emits a canned-but-realistic telemetry bundle (Frida JSONL + logcat + dumpsys)
to the object store. This exercises the entire dynamic pipeline — provision → stage →
execute → collect → teardown, normalization, detectors, persistence — with zero infra,
so the orchestration logic is verified independently of Genymotion.

It is NOT a substitute for real detonation; selecting it is explicit (``SANDBOX_BACKEND
=fake``) and the resulting report is tagged with environment backend "fake".
"""

from __future__ import annotations

import uuid

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

# A canned "spyware" run: C2 to a public IP, SMS exfil, dropped+loaded dex, exec, etc.
_FAKE_FRIDA = "\n".join([
    '{"t":"ipc","api":"aegis.hooks.installed","ts":1000}',
    '{"t":"telephony","api":"TelephonyManager.getDeviceId","value":"3556...","ts":1100}',
    '{"t":"location","api":"getLastKnownLocation","provider":"gps","ts":1200}',
    '{"t":"file","api":"FileOutputStream","path":"/data/data/com.fake/files/payload.dex","mode":"write","ts":1300}',
    '{"t":"dex","api":"DexClassLoader","path":"/data/data/com.fake/files/payload.dex","ts":1400}',
    '{"t":"http","api":"URL.openConnection","url":"http://45.155.205.10/gate.php","ts":1500}',
    '{"t":"network","api":"Socket.connect","host":"45.155.205.10","port":443,"protocol":"tcp","ts":1550}',
    '{"t":"sms","api":"SmsManager.sendTextMessage","dest":"+10000000000","body":"otp:123456","ts":1600}',
    '{"t":"exec","api":"Runtime.exec","cmd":"su -c id","ts":1700}',
])
_FAKE_LOGCAT = (
    "06-28 15:04:51.100  1234  1234 I ActivityManager: Start proc com.fake for activity\n"
    "06-28 15:04:51.200  1234  1250 I ActivityManager: START u0 {cmp=com.fake/.MainActivity}\n"
)
_FAKE_DUMPSYS = (
    "    requested permissions:\n"
    "      android.permission.INTERNET\n"
    "      android.permission.SEND_SMS\n"
    "      android.permission.ACCESS_FINE_LOCATION\n"
    "    runtime permissions:\n"
    "      android.permission.SEND_SMS: granted=true\n"
    "      android.permission.ACCESS_FINE_LOCATION: granted=true\n"
)


class FakeOrchestrator(SandboxOrchestrator):
    supported_os = frozenset({TargetOS.ANDROID, TargetOS.LINUX, TargetOS.WINDOWS})

    def __init__(self, settings=None, store=None):
        self.settings = settings
        self.store = store

    def provision(self, analysis_id: str, spec: EnvironmentSpec) -> SandboxSession:
        return SandboxSession(
            session_id=f"fake-{uuid.uuid4().hex[:12]}",
            analysis_id=analysis_id,
            spec=spec,
            snapshot_id="fake-clean",
            extra={"package": "com.fake.sample"},
        )

    def stage_sample(self, session: SandboxSession, sample_ref: str) -> None:
        session.extra["sample_ref"] = sample_ref

    def execute(self, session: SandboxSession, budget: ExecutionBudget) -> DetonationResult:
        session.extra["frida_jsonl"] = _FAKE_FRIDA
        return DetonationResult(
            session_id=session.session_id, analysis_id=session.analysis_id,
            completed=True, runtime_seconds=2.0, exit_reason="finished",
        )

    def collect(self, session: SandboxSession) -> DetonationResult:
        refs = [
            self._upload(session, "frida.jsonl", session.extra.get("frida_jsonl", _FAKE_FRIDA)),
            self._upload(session, "logcat.txt", _FAKE_LOGCAT),
            self._upload(session, "dumpsys.txt", _FAKE_DUMPSYS),
        ]
        return DetonationResult(
            session_id=session.session_id, analysis_id=session.analysis_id,
            completed=True, runtime_seconds=0.0, exit_reason="collected",
            raw_refs=[r for r in refs if r], artifact_refs=[r for r in refs if r],
        )

    def teardown(self, session: SandboxSession) -> RollbackResult:
        return RollbackResult(session.session_id, rolled_back=True, verified=True, detail="fake reset")

    def reap_orphans(self, older_than_seconds: int) -> list[str]:
        return []

    def _upload(self, session: SandboxSession, name: str, text: str) -> str | None:
        if self.store is None:
            return None
        bucket = getattr(self.settings, "s3_bucket_artifacts", "aegis-artifacts")
        key = f"{session.analysis_id}/dynamic/{name}"
        return self.store.put(bucket, key, text.encode(), content_type="text/plain")


register_backend("fake", FakeOrchestrator)

"""Dynamic-analysis tests: normalizers, detectors, and the fake-backend pipeline."""

from __future__ import annotations

from aegis.dynamic.analyze import build_report
from aegis.dynamic.models import DynamicEnvironment, EventCategory
from aegis.dynamic.normalize import (
    parse_dumpsys_permissions,
    parse_frida_events,
    parse_logcat,
)

FRIDA = "\n".join([
    '{"t":"http","api":"URL.openConnection","url":"http://45.155.205.10/gate.php","ts":1500}',
    '{"t":"sms","api":"SmsManager.sendTextMessage","dest":"+10000000000","body":"otp","ts":1600}',
    '{"t":"dex","api":"DexClassLoader","path":"/data/data/x/files/p.dex","ts":1400}',
    '{"t":"file","api":"FileOutputStream","path":"/data/data/x/files/p.dex","mode":"write","ts":1300}',
    '{"t":"exec","api":"Runtime.exec","cmd":"su -c id","ts":1700}',
    '{"t":"telephony","api":"TelephonyManager.getDeviceId","value":"355","ts":1100}',
    'not-json-should-be-skipped',
])
LOGCAT = (
    "06-28 15:04:51.100  1234  1234 I ActivityManager: Start proc com.x for activity\n"
    "06-28 15:04:51.200  1234  1250 I ActivityManager: START u0 {cmp=com.x/.Main}\n"
)
DUMPSYS = (
    "    requested permissions:\n"
    "      android.permission.SEND_SMS\n"
    "      android.permission.INTERNET\n"
    "    runtime permissions:\n"
    "      android.permission.SEND_SMS: granted=true\n"
)


class TestNormalizers:
    def test_frida_parsing_skips_bad_lines(self):
        events = parse_frida_events(FRIDA)
        assert len(events) == 6  # the non-JSON line is dropped
        cats = {e.category for e in events}
        assert EventCategory.NETWORK in cats and EventCategory.SMS in cats

    def test_frida_object_values(self):
        events = {e.action: e for e in parse_frida_events(FRIDA)}
        assert events["URL.openConnection"].object.value == "http://45.155.205.10/gate.php"
        assert events["SmsManager.sendTextMessage"].object.value == "+10000000000"

    def test_logcat_lifts_components(self):
        events = parse_logcat(LOGCAT)
        actions = {e.action for e in events}
        assert "start_process" in actions
        assert "start_component" in actions

    def test_dumpsys_permissions(self):
        requested, granted = parse_dumpsys_permissions(DUMPSYS)
        assert "android.permission.SEND_SMS" in requested
        assert "android.permission.SEND_SMS" in granted


class TestDynamicReport:
    def _report(self):
        return build_report(
            package="com.x", profile="standard",
            environment=DynamicEnvironment(backend="fake"),
            frida_jsonl=FRIDA, logcat=LOGCAT, dumpsys=DUMPSYS,
        )

    def test_rollups(self):
        r = self._report()
        assert r.event_count >= 6
        assert any(p.host == "45.155.205.10" for p in r.network_peers)
        assert "/data/data/x/files/p.dex" in r.dropped_files
        assert "/data/data/x/files/p.dex" in r.loaded_dex

    def test_detectors_fire(self):
        ids = {i.id for i in self._report().indicators}
        assert "dyn.runtime_c2" in ids
        assert "dyn.sms_sent" in ids
        assert "dyn.dropper_chain" in ids        # dropped == loaded dex
        assert "dyn.command_exec" in ids
        assert "dyn.identifier_harvest" in ids

    def test_dropper_chain_is_critical(self):
        chain = next(i for i in self._report().indicators if i.id == "dyn.dropper_chain")
        assert chain.severity.value == "critical"


def _reset_caches():
    import aegis.core.config as cfg
    import aegis.db.base as dbb
    import aegis.storage.factory as sf

    cfg.get_settings.cache_clear()
    dbb.get_engine.cache_clear()
    dbb.get_sessionmaker.cache_clear()
    sf.get_object_store.cache_clear()


class TestDynamicPipeline:
    """Full detonation lifecycle via the fake backend — no Genymotion needed."""

    def test_detonation_end_to_end(self, tmp_path, monkeypatch, fake_apk):
        import uuid

        from sqlalchemy import select

        monkeypatch.setenv("AEGIS_ENV", "test")
        monkeypatch.setenv("DATABASE_URL", f"sqlite+pysqlite:///{tmp_path/'d.db'}")
        monkeypatch.setenv("STORAGE_BACKEND", "local")
        monkeypatch.setenv("LOCAL_STORAGE_DIR", str(tmp_path / "obj"))
        monkeypatch.setenv("SANDBOX_BACKEND", "fake")
        _reset_caches()
        try:
            import aegis.db.models  # noqa: F401 - register tables
            from aegis.core.config import get_settings
            from aegis.db.base import Base, get_engine, session_scope
            from aegis.db.models import Analysis, AuditLog, Finding, Sample
            from aegis.static.common.hashing import sha256_hex
            from aegis.storage import get_object_store
            from aegis.worker.pipeline import execute_analysis
            Base.metadata.create_all(get_engine())

            s = get_settings()
            store = get_object_store()
            sha = sha256_hex(fake_apk)
            store.put(s.s3_bucket_samples, sha, fake_apk)

            with session_scope() as sess:
                smp = Sample(sha256=sha, file_type="apk", size=len(fake_apk),
                             original_filename="x.apk",
                             storage_ref=store.ref(s.s3_bucket_samples, sha))
                sess.add(smp)
                sess.flush()
                an = Analysis(sample_id=smp.id, profile="standard")
                sess.add(an)
                sess.flush()
                aid = str(an.id)

            res = execute_analysis(aid)
            assert res["state"] == "completed", res
            assert res["dynamic_findings"] >= 3

            with session_scope() as sess:
                an = sess.get(Analysis, uuid.UUID(aid))
                assert an.state == "completed"
                assert an.risk_score and an.risk_score > 0
                assert an.dynamic_report is not None
                assert an.dynamic_report.backend == "fake"

                dyn = sess.execute(
                    select(Finding).where(Finding.analysis_id == an.id, Finding.detector == "dynamic")
                ).scalars().all()
                assert len(dyn) >= 3

                states = [a.to_state for a in sess.execute(
                    select(AuditLog).where(AuditLog.analysis_id == an.id)
                ).scalars().all()]
                for required in ("provisioning", "running", "collecting", "processing", "completed"):
                    assert required in states, states
        finally:
            _reset_caches()

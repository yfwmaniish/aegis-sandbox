"""Tests for the Linux/ELF Docker detonation path: strace parsing, isolation, routing."""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aegis.core.enums import AnalysisProfile  # noqa: E402
from aegis.dynamic.analyze import build_report  # noqa: E402
from aegis.dynamic.models import DynamicEnvironment, EventCategory  # noqa: E402
from aegis.dynamic.normalize import parse_strace  # noqa: E402
from aegis.orchestrator.docker_linux import DockerLinuxOrchestrator  # noqa: E402
from aegis.orchestrator.windows import WindowsBackendUnavailable, WindowsOrchestrator  # noqa: E402
from aegis.static.models import FileType  # noqa: E402
from aegis.worker.pipeline import _should_detonate  # noqa: E402

_TRACE = r'''1712345678.100000 execve("/tmp/s", ["/tmp/s", "--daemon"], 0x7ffd) = 0
[pid  4210] 1712345678.200000 openat(AT_FDCWD, "/tmp/payload.bin", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 4
[pid  4210] 1712345678.210000 chmod("/tmp/payload.bin", 0755) = 0
4210 1712345678.300000 connect(5, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("45.155.205.10")}, 16) = -1 EINPROGRESS
4210 1712345678.400000 connect(6, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110) = -1 ENOENT
4210 1712345678.500000 openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 7
4210 1712345678.600000 execve("/tmp/payload.bin", ["/tmp/payload.bin"], 0x0) = 0
4210 1712345678.700000 clone(child_stack=NULL, flags=CLONE_VM) = 9001
+++ exited with 0 +++'''


# ── strace normalization ─────────────────────────────────────────────────────

def test_parse_strace_categories_and_filtering():
    evs = parse_strace(_TRACE)
    by_cat = {}
    for e in evs:
        by_cat.setdefault(e.category, []).append(e)
    # execve x2, file write + chmod, one public connect, one spawn.
    assert len(evs) == 6
    assert len(by_cat[EventCategory.EXEC]) == 2
    assert len(by_cat[EventCategory.NETWORK]) == 1
    net = by_cat[EventCategory.NETWORK][0]
    assert net.object.value == "45.155.205.10" and net.detail["port"] == 443
    assert EventCategory.PROCESS in by_cat
    # AF_UNIX socket and the read-only /etc/passwd open are filtered out.
    assert all("passwd" not in (e.object.value or "") for e in evs)
    assert all(e.object.value != "/var/run/nscd/socket" for e in evs)
    assert all(e.platform == "linux" for e in evs)


def test_strace_feeds_detectors():
    rep = build_report(package="/tmp/s", profile="standard",
                       environment=DynamicEnvironment(backend="docker", network_policy="none"),
                       strace=_TRACE, exit_reason="finished")
    ids = {i.id for i in rep.indicators}
    assert "dyn.runtime_c2" in ids
    assert "dyn.command_exec" in ids
    # network peer rolled up from the connect().
    assert any(p.host == "45.155.205.10" for p in rep.network_peers)


# ── Docker backend isolation + parsing ───────────────────────────────────────

def test_docker_run_cmd_is_locked_down():
    o = DockerLinuxOrchestrator(settings=SimpleNamespace(docker_sandbox_image="img:1"), store=None)
    cmd = o._run_cmd("aegis-x", "/host/stage", 60)
    joined = " ".join(cmd)
    assert "--network none" in joined            # isolation: no egress
    assert "--cap-drop ALL" in joined
    assert "--cap-add SYS_PTRACE" in joined       # only ptrace, for strace
    assert "--read-only" in joined
    assert "--security-opt no-new-privileges" in joined
    assert "--pids-limit" in joined and "--memory" in joined
    assert cmd[-2:] == ["img:1", "60"]
    assert "/host/stage:/sample:ro" in joined


def test_split_output_exit_reasons():
    o = DockerLinuxOrchestrator(settings=None, store=None)
    assert o._split_output("AEGIS_EXIT=0\ntrace", 0)[1] == "finished"
    assert o._split_output("AEGIS_EXIT=124\ntrace", 0)[1] == "timeout"
    assert o._split_output("AEGIS_EXIT=90\n", 0)[1] == "install_failed"
    assert o._split_output("partial", 124)[1] == "killed"
    trace, _ = o._split_output("AEGIS_EXIT=0\nline1\nline2", 0)
    assert trace == "line1\nline2"  # marker stripped from the strace body


# ── routing + honest Windows backend ─────────────────────────────────────────

def test_should_detonate_backend_matrix():
    def s(backend):
        return SimpleNamespace(sandbox_backend=backend)
    std = AnalysisProfile.STANDARD
    assert _should_detonate(s("docker"), std, FileType.ELF) is True
    assert _should_detonate(s("docker"), std, FileType.APK) is False
    assert _should_detonate(s("avd"), std, FileType.APK) is True
    assert _should_detonate(s("avd"), std, FileType.ELF) is False
    assert _should_detonate(s("windows"), std, FileType.PE) is True
    assert _should_detonate(s("docker"), AnalysisProfile.STATIC_ONLY, FileType.ELF) is False
    assert _should_detonate(s(""), std, FileType.ELF) is False


def test_windows_backend_refuses_without_config():
    w = WindowsOrchestrator(settings=SimpleNamespace(), store=None)
    spec = SimpleNamespace()
    try:
        w.provision("aid", spec)  # type: ignore[arg-type]
        raised = False
    except WindowsBackendUnavailable:
        raised = True
    assert raised, "unconfigured Windows backend must refuse (no fabricated telemetry)"

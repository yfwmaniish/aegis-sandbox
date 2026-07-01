"""Docker-based Linux (ELF) detonation backend — real, isolated, no license.

One run: build/verify a minimal analysis image (Debian + strace) once, then detonate the
ELF inside a locked-down disposable container — **no network** (``--network none``),
read-only root filesystem, tmpfs scratch, all Linux capabilities dropped except the one
``strace`` needs (``SYS_PTRACE``), ``no-new-privileges``, and pid/memory/CPU caps plus a
wall-clock ``timeout``. ``strace -f -ttt`` records the sample's syscalls (execve /
connect / file writes / spawns); the container is torn down with ``--rm``. The sample
never touches the host: it runs only inside the throwaway container with no egress.

Requires Docker (Desktop/Engine) with a Linux-container daemon running. The one-time
image build needs internet; detonations themselves are fully offline.
"""

from __future__ import annotations

import shutil
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
from aegis.orchestrator.isolation import IsolationError
from aegis.orchestrator.shell import have, run

_DEFAULT_IMAGE = "aegis-linux-sandbox:latest"
_TRACE_SYSCALLS = ("execve,execveat,connect,sendto,sendmsg,open,openat,"
                   "rename,renameat,unlink,unlinkat,chmod,fchmodat,clone,fork,vfork")

_DOCKERFILE = """FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends strace ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY analyze.sh /analyze.sh
RUN chmod +x /analyze.sh
ENTRYPOINT ["/analyze.sh"]
"""

# Runs inside the container. $1 = timeout seconds. strace output -> container stdout so
# the host reads it without a writable bind mount. The sample's own stdio is isolated.
_ANALYZE_SH = (
    "#!/bin/sh\n"
    'T="${1:-60}"\n'
    "cp /sample/sample /tmp/s 2>/dev/null || { echo AEGIS_EXIT=90; exit 0; }\n"
    "chmod +x /tmp/s 2>/dev/null\n"
    "strace -f -ttt -e trace=" + _TRACE_SYSCALLS + " -o /tmp/trace.log "
    'timeout "$T" /tmp/s >/tmp/out.log 2>/tmp/err.log\n'
    'echo "AEGIS_EXIT=$?"\n'
    "cat /tmp/trace.log 2>/dev/null\n"
)


class DockerUnavailable(RuntimeError):
    """Raised when Docker / a Linux-container daemon is not available."""


class DockerLinuxOrchestrator(SandboxOrchestrator):
    supported_os = frozenset({TargetOS.LINUX})

    def __init__(self, settings=None, store=None):
        self.settings = settings
        self.store = store
        self.image = getattr(settings, "docker_sandbox_image", None) or _DEFAULT_IMAGE

    # ── preflight ────────────────────────────────────────────────────────────
    @staticmethod
    def preflight() -> dict[str, bool]:
        cli = have("docker")
        daemon = bool(cli) and run(["docker", "info", "--format", "{{.OSType}}"], timeout=15).ok
        return {"docker": cli, "daemon": daemon}

    def _daemon_ok(self) -> bool:
        return have("docker") and run(["docker", "info", "--format", "{{.OSType}}"], timeout=15).ok

    def _image_exists(self) -> bool:
        return run(["docker", "image", "inspect", self.image], timeout=30).ok

    def _build_image(self) -> None:
        ctx = Path(tempfile.mkdtemp(prefix="aegis-docker-ctx-"))
        try:
            (ctx / "analyze.sh").write_text(_ANALYZE_SH, encoding="utf-8", newline="\n")
            (ctx / "Dockerfile").write_text(_DOCKERFILE, encoding="utf-8", newline="\n")
            res = run(["docker", "build", "-t", self.image, str(ctx)], timeout=900)
            if not res.ok:
                raise DockerUnavailable(
                    f"failed to build the analysis image '{self.image}' (needs internet "
                    f"once). Build it manually or check Docker.\n{(res.stderr or res.stdout)[-800:]}"
                )
        finally:
            shutil.rmtree(ctx, ignore_errors=True)

    # ── lifecycle ────────────────────────────────────────────────────────────
    def provision(self, analysis_id: str, spec: EnvironmentSpec) -> SandboxSession:
        if not self._daemon_ok():
            raise DockerUnavailable(
                "Docker is not available or no Linux-container daemon is running. "
                "Install/start Docker Desktop (or Engine) and retry."
            )
        if not self._image_exists():
            self._build_image()
        return SandboxSession(
            session_id=f"docker-{uuid.uuid4().hex[:12]}",
            analysis_id=analysis_id, spec=spec, snapshot_id=self.image,
            extra={"container": f"aegis-{analysis_id[:8]}-{uuid.uuid4().hex[:6]}",
                   "device_name": self.image, "isolated": "true"},
        )

    def stage_sample(self, session: SandboxSession, sample_ref: str) -> None:
        data = self._fetch_sample(sample_ref)
        stage_dir = Path(tempfile.mkdtemp(prefix="aegis-elf-"))
        (stage_dir / "sample").write_bytes(data)
        session.extra["stage_dir"] = str(stage_dir)

    def execute(self, session: SandboxSession, budget: ExecutionBudget) -> DetonationResult:
        stage_dir = session.extra.get("stage_dir")
        if not stage_dir:
            return DetonationResult(
                session_id=session.session_id, analysis_id=session.analysis_id,
                completed=False, runtime_seconds=0.0, exit_reason="install_failed",
            )
        # Isolation gate: this backend detonates only with the network disabled. If
        # isolation is required, the invariant is structural (--network none below).
        require = getattr(self.settings, "dynamic_require_isolation", True)
        cmd = self._run_cmd(session.extra["container"], stage_dir, budget.max_runtime_seconds)
        if require and "none" not in cmd:  # defensive: never detonate with egress
            raise IsolationError("refusing to detonate: container network is not disabled")

        start = time.time()
        res = run(cmd, timeout=budget.max_runtime_seconds + 60)
        trace, exit_reason = self._split_output(res.stdout, res.rc)
        session.extra["strace"] = trace
        if not res.ok and not trace:
            session.extra["docker_error"] = (res.stderr or res.stdout).strip()[:500]
            exit_reason = "crashed"
        return DetonationResult(
            session_id=session.session_id, analysis_id=session.analysis_id,
            completed=bool(trace), runtime_seconds=round(time.time() - start, 2),
            exit_reason=exit_reason,
        )

    def collect(self, session: SandboxSession) -> DetonationResult:
        ref = self._upload(session, "strace.txt", session.extra.get("strace", ""))
        refs = [ref] if ref else []
        return DetonationResult(
            session_id=session.session_id, analysis_id=session.analysis_id,
            completed=True, runtime_seconds=0.0, exit_reason="collected",
            raw_refs=refs, artifact_refs=refs,
        )

    def teardown(self, session: SandboxSession) -> RollbackResult:
        # --rm removes the container, but force-remove in case it lingered, then wipe
        # the host staging dir (the only place the sample bytes touched the host).
        cname = session.extra.get("container")
        if cname:
            run(["docker", "rm", "-f", cname], timeout=30)
        stage_dir = session.extra.get("stage_dir")
        if stage_dir:
            shutil.rmtree(stage_dir, ignore_errors=True)
        return RollbackResult(
            session_id=session.session_id, rolled_back=True, verified=True,
            detail="container removed (--rm) + host staging wiped",
        )

    def reap_orphans(self, older_than_seconds: int) -> list[str]:
        res = run(["docker", "ps", "-q", "-f", "name=aegis-"], timeout=30)
        reaped: list[str] = []
        for cid in res.stdout.split():
            if run(["docker", "rm", "-f", cid], timeout=30).ok:
                reaped.append(cid)
        return reaped

    # ── helpers ──────────────────────────────────────────────────────────────
    def _run_cmd(self, cname: str, stage_dir: str, seconds: int) -> list[str]:
        """Build the locked-down `docker run` command (isolated, no egress)."""
        return [
            "docker", "run", "--rm", "--name", cname,
            "--network", "none",                       # no egress — isolation invariant
            "--read-only", "--tmpfs", "/tmp:exec,size=128m",
            "--cap-drop", "ALL", "--cap-add", "SYS_PTRACE",  # ptrace for strace only
            "--security-opt", "no-new-privileges",
            "--pids-limit", "256", "--memory", "768m", "--cpus", "1",
            "-v", f"{stage_dir}:/sample:ro",
            self.image, str(seconds),
        ]

    @staticmethod
    def _split_output(stdout: str, rc: int) -> tuple[str, str]:
        """Separate the AEGIS_EXIT marker from the strace body; derive an exit reason."""
        exit_code = None
        lines = stdout.splitlines()
        body: list[str] = []
        for ln in lines:
            if ln.startswith("AEGIS_EXIT="):
                try:
                    exit_code = int(ln.split("=", 1)[1].strip())
                except ValueError:
                    exit_code = None
            else:
                body.append(ln)
        trace = "\n".join(body)
        if rc == 124:
            reason = "killed"           # our outer run() timeout tripped
        elif exit_code == 124:
            reason = "timeout"          # inner `timeout` stopped the sample
        elif exit_code == 90:
            reason = "install_failed"
        elif exit_code is not None:
            reason = "finished"
        else:
            reason = "unknown"
        return trace, reason

    def _fetch_sample(self, sample_ref: str) -> bytes:
        if self.store is None:
            raise DockerUnavailable("no object store configured for sample staging")
        _, _, rest = sample_ref.partition("://")
        bucket, _, key = rest.partition("/")
        return self.store.get(bucket, key)

    def _upload(self, session: SandboxSession, name: str, text: str) -> str | None:
        if self.store is None or not text:
            return None
        bucket = getattr(self.settings, "s3_bucket_artifacts", "aegis-artifacts")
        return self.store.put(bucket, f"{session.analysis_id}/dynamic/{name}",
                              text.encode("utf-8", "replace"), content_type="text/plain")


register_backend("docker", DockerLinuxOrchestrator)

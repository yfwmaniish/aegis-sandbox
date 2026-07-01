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


# --- sinkhole (live network-capture) image ---------------------------------
# Answers every DNS query with its own IP and logs it; logs every HTTP request. Runs on a
# Docker --internal network (no route off the host), so the sample *attempts* its C2 and
# we record the endpoints, but nothing ever leaves the machine.
_SINKHOLE_PY = r'''
import socket, struct, threading, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
def log(m): sys.stdout.write(m+"\n"); sys.stdout.flush()
def own_ip():
    try: return socket.gethostbyname(socket.gethostname())
    except Exception: return "127.0.0.1"
IP = own_ip()
def qname(data):
    off=12; parts=[]
    while off < len(data):
        n=data[off]
        if n==0: off+=1; break
        parts.append(data[off+1:off+1+n].decode("ascii","replace")); off+=1+n
    return ".".join(parts), off
def dns():
    s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("0.0.0.0",53))
    ipb=socket.inet_aton(IP)
    while True:
        try:
            data,addr=s.recvfrom(512)
            if len(data)<12: continue
            name,end=qname(data); log("DNS "+name)
            hdr=data[:2]+struct.pack(">HHHHH",0x8180,1,1,0,0)
            q=data[12:end+4]
            ans=b"\xc0\x0c"+struct.pack(">HHIH",1,1,60,4)+ipb
            s.sendto(hdr+q+ans, addr)
        except Exception as e: log("ERR dns "+str(e))
class H(BaseHTTPRequestHandler):
    def _h(self,m):
        log("HTTP %s %s %s"%(m, self.headers.get("Host","-"), self.path))
        try:
            self.send_response(200); self.send_header("Content-Length","2"); self.end_headers()
            self.wfile.write(b"ok")
        except Exception: pass
    def do_GET(self): self._h("GET")
    def do_POST(self): self._h("POST")
    def do_HEAD(self): self._h("HEAD")
    def do_PUT(self): self._h("PUT")
    def log_message(self,*a): pass
log("SINKHOLE up ip="+IP)
threading.Thread(target=dns, daemon=True).start()
HTTPServer(("0.0.0.0",80), H).serve_forever()
'''

_SINKHOLE_DOCKERFILE = """FROM python:3.12-slim
COPY sinkhole.py /sinkhole.py
ENTRYPOINT ["python", "-u", "/sinkhole.py"]
"""


class DockerUnavailable(RuntimeError):
    """Raised when Docker / a Linux-container daemon is not available."""


class DockerLinuxOrchestrator(SandboxOrchestrator):
    supported_os = frozenset({TargetOS.LINUX})

    def __init__(self, settings=None, store=None):
        self.settings = settings
        self.store = store
        self.image = getattr(settings, "docker_sandbox_image", None) or _DEFAULT_IMAGE
        self.sinkhole = bool(getattr(settings, "docker_sinkhole", False))
        self.sinkhole_image = getattr(settings, "docker_sinkhole_image", None) or "aegis-sinkhole:latest"

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

    def _build_sinkhole_image(self) -> None:
        ctx = Path(tempfile.mkdtemp(prefix="aegis-sink-ctx-"))
        try:
            (ctx / "sinkhole.py").write_text(_SINKHOLE_PY, encoding="utf-8", newline="\n")
            (ctx / "Dockerfile").write_text(_SINKHOLE_DOCKERFILE, encoding="utf-8", newline="\n")
            res = run(["docker", "build", "-t", self.sinkhole_image, str(ctx)], timeout=900)
            if not res.ok:
                raise DockerUnavailable(
                    f"failed to build the sinkhole image '{self.sinkhole_image}'.\n"
                    f"{(res.stderr or res.stdout)[-800:]}")
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
        if self.sinkhole and not run(
                ["docker", "image", "inspect", self.sinkhole_image], timeout=30).ok:
            self._build_sinkhole_image()
        sid8 = uuid.uuid4().hex[:6]
        return SandboxSession(
            session_id=f"docker-{uuid.uuid4().hex[:12]}",
            analysis_id=analysis_id, spec=spec, snapshot_id=self.image,
            extra={"container": f"aegis-{analysis_id[:8]}-{sid8}",
                   "device_name": self.image, "isolated": "true",
                   "mode": "sinkhole" if self.sinkhole else "airgap"},
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
        start = time.time()
        # Both modes are isolated by construction: air-gap uses --network none; sinkhole
        # uses a Docker --internal network (no route off the host). No real egress either way.
        if self.sinkhole:
            res = self._execute_sinkhole(session, stage_dir, budget)
        else:
            cmd = self._run_cmd(session.extra["container"], stage_dir, budget.max_runtime_seconds)
            require = getattr(self.settings, "dynamic_require_isolation", True)
            if require and "none" not in cmd:  # defensive: never detonate with egress
                raise IsolationError("refusing to detonate: container network is not disabled")
            res = run(cmd, timeout=budget.max_runtime_seconds + 60)

        trace, exit_reason = self._split_output(res.stdout, res.rc)
        session.extra["strace"] = trace
        if not res.ok and not trace:
            session.extra["docker_error"] = (res.stderr or res.stdout).strip()[:500]
            exit_reason = "crashed"
        return DetonationResult(
            session_id=session.session_id, analysis_id=session.analysis_id,
            completed=bool(trace) or bool(session.extra.get("sinkhole")),
            runtime_seconds=round(time.time() - start, 2), exit_reason=exit_reason,
        )

    def _execute_sinkhole(self, session, stage_dir, budget):
        """Run the sample on an --internal network with a DNS/HTTP sinkhole attached."""
        sid = session.extra["container"].rsplit("-", 1)[-1]
        net = f"aegis-sinknet-{sid}"
        sink = f"aegis-sink-{sid}"
        session.extra["_sink_net"] = net
        session.extra["_sink_c"] = sink
        run(["docker", "network", "create", "--internal", net], timeout=60)
        run(["docker", "run", "-d", "--name", sink, "--network", net,
             "--cap-drop", "ALL", "--cap-add", "NET_BIND_SERVICE",
             self.sinkhole_image], timeout=120)
        ip = run(["docker", "inspect", "-f",
                  "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", sink],
                 timeout=30).stdout.strip()
        time.sleep(2)  # let the sinkhole bind :53/:80 before the sample runs
        cmd = self._run_cmd_sinkhole(session.extra["container"], stage_dir, net,
                                     ip or "", budget.max_runtime_seconds)
        res = run(cmd, timeout=budget.max_runtime_seconds + 60)
        session.extra["sinkhole"] = run(["docker", "logs", sink], timeout=60).stdout
        return res

    def collect(self, session: SandboxSession) -> DetonationResult:
        refs = [
            self._upload(session, "strace.txt", session.extra.get("strace", "")),
            self._upload(session, "sinkhole.txt", session.extra.get("sinkhole", "")),
        ]
        refs = [r for r in refs if r]
        return DetonationResult(
            session_id=session.session_id, analysis_id=session.analysis_id,
            completed=True, runtime_seconds=0.0, exit_reason="collected",
            raw_refs=refs, artifact_refs=refs,
        )

    def teardown(self, session: SandboxSession) -> RollbackResult:
        # --rm removes the sample container, but force-remove in case it lingered; also
        # tear down the sinkhole container + internal network; then wipe the host staging
        # dir (the only place the sample bytes touched the host).
        cname = session.extra.get("container")
        if cname:
            run(["docker", "rm", "-f", cname], timeout=30)
        sink = session.extra.get("_sink_c")
        if sink:
            run(["docker", "rm", "-f", sink], timeout=30)
        net = session.extra.get("_sink_net")
        if net:
            run(["docker", "network", "rm", net], timeout=30)
        stage_dir = session.extra.get("stage_dir")
        if stage_dir:
            shutil.rmtree(stage_dir, ignore_errors=True)
        detail = ("sample + sinkhole containers removed, internal network + host staging wiped"
                  if sink else "container removed (--rm) + host staging wiped")
        return RollbackResult(
            session_id=session.session_id, rolled_back=True, verified=True, detail=detail,
        )

    def reap_orphans(self, older_than_seconds: int) -> list[str]:
        res = run(["docker", "ps", "-q", "-f", "name=aegis-"], timeout=30)
        reaped: list[str] = []
        for cid in res.stdout.split():
            if run(["docker", "rm", "-f", cid], timeout=30).ok:
                reaped.append(cid)
        return reaped

    # ── helpers ──────────────────────────────────────────────────────────────
    _ISOLATION_FLAGS = [
        "--read-only", "--tmpfs", "/tmp:exec,size=128m",
        "--cap-drop", "ALL", "--cap-add", "SYS_PTRACE",  # ptrace for strace only
        "--security-opt", "no-new-privileges",
        "--pids-limit", "256", "--memory", "768m", "--cpus", "1",
    ]

    def _run_cmd(self, cname: str, stage_dir: str, seconds: int) -> list[str]:
        """Build the locked-down `docker run` command (air-gapped, no network)."""
        return [
            "docker", "run", "--rm", "--name", cname,
            "--network", "none",                       # no egress — isolation invariant
            *self._ISOLATION_FLAGS,
            "-v", f"{stage_dir}:/sample:ro",
            self.image, str(seconds),
        ]

    def _run_cmd_sinkhole(self, cname: str, stage_dir: str, net: str, dns_ip: str,
                          seconds: int) -> list[str]:
        """Same lock-down, but on a Docker --internal network (no host egress) with the
        sinkhole as DNS — so the sample can *attempt* its C2 and we capture it."""
        dns = ["--dns", dns_ip] if dns_ip else []
        return [
            "docker", "run", "--rm", "--name", cname,
            "--network", net, *dns,                    # --internal net = no real egress
            *self._ISOLATION_FLAGS,
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

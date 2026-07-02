"""JAR (Java archive) static analysis.

A JAR is a ZIP with a manifest and ``.class`` entries. Malicious JARs (RAT loaders,
cross-platform droppers) reach for a small set of Java APIs: process execution, dynamic
class loading, and network fetch. We read the manifest's ``Main-Class`` and scan the
class bytes for those API strings (constant-pool UTF-8 entries make them visible without
decompiling). Dependency-free.
"""

from __future__ import annotations

import zipfile
from io import BytesIO

from aegis.static.models import JARFeatures, Severity, SuspiciousIndicator

# api marker (as it appears in the constant pool) -> label.
_SUSPICIOUS = {
    b"java/lang/Runtime": "Runtime.exec", b"ProcessBuilder": "ProcessBuilder",
    b"java/net/URLClassLoader": "URLClassLoader", b"defineClass": "defineClass",
    b"javax/script": "ScriptEngine", b"java/net/URL": "java.net.URL",
    b"java/net/HttpURLConnection": "HttpURLConnection", b"java/net/Socket": "Socket",
    b"cmd.exe": "cmd.exe", b"/bin/sh": "/bin/sh", b"getRuntime": "getRuntime",
    b"java/lang/reflect": "reflection", b"sun.misc.Unsafe": "Unsafe",
    b"javax/crypto": "javax.crypto", b"java/util/Base64": "Base64",
}


def analyze(data: bytes) -> tuple[JARFeatures, list[SuspiciousIndicator]]:
    feats = JARFeatures()
    apis: set[str] = set()
    try:
        with zipfile.ZipFile(BytesIO(data)) as zf:
            names = zf.namelist()
            feats.entry_count = len(names)
            feats.class_count = sum(1 for n in names if n.endswith(".class"))
            feats.has_manifest = "META-INF/MANIFEST.MF" in names
            if feats.has_manifest:
                try:
                    mf = zf.read("META-INF/MANIFEST.MF").decode("utf-8", "replace")
                    for line in mf.splitlines():
                        if line.lower().startswith("main-class:"):
                            feats.main_class = line.split(":", 1)[1].strip()
                except KeyError:
                    pass
            scanned = 0
            for n in names:
                if not n.endswith(".class") or scanned >= 400:
                    continue
                scanned += 1
                try:
                    blob = zf.read(n)
                except (KeyError, zipfile.BadZipFile):
                    continue
                for marker, label in _SUSPICIOUS.items():
                    if marker in blob:
                        apis.add(label)
    except (zipfile.BadZipFile, OSError):
        return feats, []

    feats.suspicious_apis = sorted(apis)
    ind: list[SuspiciousIndicator] = []
    execers = {"Runtime.exec", "ProcessBuilder", "getRuntime", "cmd.exe", "/bin/sh"}
    loaders = {"URLClassLoader", "defineClass", "ScriptEngine", "reflection", "Unsafe"}
    if execers & apis:
        ind.append(SuspiciousIndicator(
            id="jar.command_exec", title="JAR invokes OS command execution",
            severity=Severity.HIGH, confidence=0.7,
            observed_facts=sorted(execers & apis),
            inference="Runtime.exec/ProcessBuilder spawn native commands — common in Java "
                      "RATs and cross-platform droppers.",
            evidence=sorted(execers & apis),
        ))
    if loaders & apis:
        ind.append(SuspiciousIndicator(
            id="jar.dynamic_load", title="JAR loads code dynamically",
            severity=Severity.HIGH, confidence=0.65,
            observed_facts=sorted(loaders & apis),
            inference="Runtime class loading / reflection is used to fetch and run a "
                      "second stage — the defining behaviour of a Java loader.",
            evidence=sorted(loaders & apis),
        ))
    return feats, ind

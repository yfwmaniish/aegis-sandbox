"""Versioned static-analysis output schema.

This is the deterministic, schema-versioned contract every static analyzer fills
(TR-STA-01). Downstream services (DB persistence, detectors, similarity, report)
consume :class:`StaticReport` and nothing analyzer-internal. Bump
``STATIC_SCHEMA_VERSION`` on any breaking field change.

Design notes:
- Pydantic v2 models so the report serialises straight to JSON for storage/API.
- ``SuspiciousIndicator`` mirrors the TRD generic finding contract: it separates
  ``observed_facts`` (what the parser literally saw) from ``inference`` (the
  hypothesis), per TR-DET-02 / NFR-18.
- Each format gets its own optional sub-model; exactly one is populated per file.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel, Field

STATIC_SCHEMA_VERSION = "1.0"


class FileType(str, Enum):
    PE = "pe"
    ELF = "elf"
    APK = "apk"
    DEX = "dex"
    MACHO = "macho"
    ZIP = "zip"
    PDF = "pdf"
    OFFICE = "office"
    SCRIPT = "script"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


def _utcnow() -> datetime:
    return datetime.now(UTC)


class SuspiciousIndicator(BaseModel):
    """A single heuristic flag, evidence-first (observed fact vs. inference)."""

    id: str = Field(description="Stable rule id, e.g. 'pe.high_entropy_text_section'")
    title: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    observed_facts: list[str] = Field(default_factory=list)
    inference: str = ""
    evidence: list[str] = Field(default_factory=list, description="Pointers: section names, API names, offsets")


class IOCEntry(BaseModel):
    type: str
    value: str
    confidence: float = Field(ge=0.0, le=1.0)
    source: str


class StringSummary(BaseModel):
    count: int = 0
    truncated: bool = False
    interesting: dict[str, list[str]] = Field(default_factory=dict)
    # Full string lists are large; kept out of the report by default and stored
    # as a separate artifact. Samples are surfaced via ``interesting``.


class HashSummary(BaseModel):
    sha256: str
    sha1: str
    md5: str
    tlsh: str | None = None
    imphash: str | None = None  # PE import hash, when applicable


class EntropySummary(BaseModel):
    overall: float
    packing_likelihood: str = "low"  # low|medium|high
    high_entropy_regions: int = 0


# ── Section / symbol building blocks ─────────────────────────────────────────


class SectionInfo(BaseModel):
    name: str
    virtual_address: int | None = None
    virtual_size: int | None = None
    raw_size: int | None = None
    entropy: float | None = None
    flags: list[str] = Field(default_factory=list)


class ImportInfo(BaseModel):
    library: str
    functions: list[str] = Field(default_factory=list)


# ── Per-format feature blocks ────────────────────────────────────────────────


class PEFeatures(BaseModel):
    machine: str | None = None
    subsystem: str | None = None
    is_dll: bool = False
    timestamp: str | None = None  # PE compile timestamp (RFC3339 or raw)
    entry_point: int | None = None
    image_base: int | None = None
    sections: list[SectionInfo] = Field(default_factory=list)
    imports: list[ImportInfo] = Field(default_factory=list)
    exports: list[str] = Field(default_factory=list)
    resources: list[str] = Field(default_factory=list)
    is_signed: bool = False
    signer: str | None = None
    tls_callbacks: int = 0
    debug_pdb_path: str | None = None


class ELFFeatures(BaseModel):
    arch: str | None = None
    elf_type: str | None = None  # EXEC/DYN/REL/CORE
    endianness: str | None = None
    interpreter: str | None = None
    is_stripped: bool = False
    is_static: bool = False
    sections: list[SectionInfo] = Field(default_factory=list)
    imported_symbols: list[str] = Field(default_factory=list)
    needed_libraries: list[str] = Field(default_factory=list)
    rpath: list[str] = Field(default_factory=list)
    has_text_relocations: bool = False


class CertInfo(BaseModel):
    subject: str | None = None
    issuer: str | None = None
    serial: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    sha256: str | None = None
    is_debug_cert: bool = False  # Android default debug-signing cert


class AndroidComponent(BaseModel):
    type: str  # activity|service|receiver|provider
    name: str
    exported: bool = False
    permission: str | None = None
    intent_actions: list[str] = Field(default_factory=list)


class APKFeatures(BaseModel):
    package: str | None = None
    version_name: str | None = None
    version_code: int | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None
    main_activity: str | None = None
    permissions: list[str] = Field(default_factory=list)
    dangerous_permissions: list[str] = Field(default_factory=list)
    custom_permissions: list[str] = Field(default_factory=list)
    components: list[AndroidComponent] = Field(default_factory=list)
    uses_features: list[str] = Field(default_factory=list)
    activities: int = 0
    services: int = 0
    receivers: int = 0
    providers: int = 0
    certificates: list[CertInfo] = Field(default_factory=list)
    suspicious_apis: list[str] = Field(default_factory=list)
    requests_accessibility: bool = False
    requests_device_admin: bool = False
    uses_native_libs: list[str] = Field(default_factory=list)
    dex_count: int = 0


class PDFFeatures(BaseModel):
    version: str | None = None
    object_count: int = 0
    stream_count: int = 0
    is_encrypted: bool = False
    has_javascript: bool = False
    js_count: int = 0
    has_openaction: bool = False
    has_additional_actions: bool = False   # /AA
    has_launch: bool = False
    has_embedded_files: bool = False
    embedded_count: int = 0
    has_uri: bool = False
    has_acroform: bool = False
    has_xfa: bool = False
    has_richmedia: bool = False            # Flash / embedded media
    has_jbig2: bool = False                # historically exploited decoder
    has_gotor: bool = False                # /GoToR remote go-to
    keyword_counts: dict[str, int] = Field(default_factory=dict)


class OfficeFeatures(BaseModel):
    container: str = "unknown"             # ole | ooxml
    doc_type: str | None = None            # word | excel | powerpoint | unknown
    has_macros: bool = False
    vba_extracted: bool = False            # whether macro *source* was recovered
    macro_streams: list[str] = Field(default_factory=list)
    macro_line_count: int = 0
    auto_exec: list[str] = Field(default_factory=list)      # AutoOpen, Document_Open, ...
    suspicious_keywords: list[str] = Field(default_factory=list)
    has_dde: bool = False
    external_targets: list[str] = Field(default_factory=list)  # remote template / links


class ScriptFeatures(BaseModel):
    language: str = "unknown"              # javascript|vbscript|powershell|batch|hta|wsf|shell
    line_count: int = 0
    char_count: int = 0
    obfuscation_score: float = 0.0         # 0..1
    obfuscation_indicators: list[str] = Field(default_factory=list)
    suspicious_apis: list[str] = Field(default_factory=list)
    has_base64_blobs: bool = False
    longest_base64: int = 0


class MachOFeatures(BaseModel):
    magic: str | None = None
    is_fat: bool = False
    archs: list[str] = Field(default_factory=list)
    filetype: str | None = None            # EXECUTE | DYLIB | BUNDLE | ...
    ncmds: int = 0
    linked_dylibs: list[str] = Field(default_factory=list)
    rpaths: list[str] = Field(default_factory=list)
    is_signed: bool = False
    is_encrypted: bool = False             # LC_ENCRYPTION_INFO present
    min_os: str | None = None
    suspicious_imports: list[str] = Field(default_factory=list)


# ── Top-level report ─────────────────────────────────────────────────────────


class StaticReport(BaseModel):
    schema_version: str = STATIC_SCHEMA_VERSION
    created_at: datetime = Field(default_factory=_utcnow)

    file_type: FileType = FileType.UNKNOWN
    detected_mime: str | None = None
    size: int = 0
    hashes: HashSummary

    analyzers_run: list[str] = Field(default_factory=list)
    # Module-isolated, non-fatal errors (TR-STA-02): module name -> message.
    analyzer_errors: dict[str, str] = Field(default_factory=dict)

    entropy: EntropySummary
    strings: StringSummary = Field(default_factory=StringSummary)
    iocs: list[IOCEntry] = Field(default_factory=list)
    indicators: list[SuspiciousIndicator] = Field(default_factory=list)

    pe: PEFeatures | None = None
    elf: ELFFeatures | None = None
    apk: APKFeatures | None = None
    pdf: PDFFeatures | None = None
    office: OfficeFeatures | None = None
    script: ScriptFeatures | None = None
    macho: MachOFeatures | None = None

    def add_error(self, module: str, exc: BaseException) -> None:
        self.analyzer_errors[module] = f"{type(exc).__name__}: {exc}"

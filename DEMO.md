# MalwareTotal — Demo Walkthrough

A scripted end-to-end demo you can run cold, plus the pitch and the honest framing.

---

## 0. Setup (once)

```bash
python -m venv .venv && . .venv/Scripts/activate     # or .venv/bin/activate
pip install -e ".[static,api,worker,dev]"
python serve.py                                       # -> http://127.0.0.1:8000/ui/
```

Optional keys in a git-ignored `.env` (never committed):
`ANTHROPIC_API_KEY` (AI narrative) · `VIRUSTOTAL_API_KEY` (VT comparison — only the SHA-256 is sent).

---

## 1. The 60-second "VirusTotal missed it" demo

The money path. Use **`Tesk APK/MarriageInvite.apk`** (a real spyware APK).

1. **Sign in** (first account becomes admin) → **upload MarriageInvite.apk** → Profile **Static only** → **Analyze**.
2. **Verdict**: `HIGH` — point at the findings: hard-coded C2 `118.196.64.77`, a **Telegram exfil channel** (`t.me/kodexhacks`), firebase/S3 data staging, network capability with no INTERNET permission declared.
3. **Visual analysis** — the **capability radar** pegs Network/C2, the **MITRE ATT&CK** row lights up (T1437.001 web C2, T1639 exfil), and the **behaviour graph** draws `sample → capabilities → 8 real endpoints`.
4. **🔍 Compare with VirusTotal** — the headline moment:
   ```
   VirusTotal:  0 / 64 engines flagged        (scanned 2026-06-18)
   Aegis:       HIGH (56/100)
   ⚠ Detection gap: Aegis caught it, all 64 VT engines missed it
   ```
5. **⬇ Export report** — a self-contained PDF-ready report opens in a new tab. **STIX 2.1 / MISP** buttons in the Threat-intel section export the IOCs + YARA/Sigma for a TIP.
6. **📊 Corpus** (top-right) — the catch-rate scoreboard: **100% flagged** across the sample set, risk distribution, top capabilities.

> One line to say while it runs: *"64 commercial AV engines say this wedding-invite app is clean. Aegis reads its behaviour and calls it spyware — hard-coded C2, a Telegram exfil channel, and silent data staging."*

CLI version of the scoreboard:
```bash
python -m aegis.cli scan "Tesk APK" --virustotal
```

---

## 2. Breadth demo — "it's not just APKs"

Drop any of these in to show coverage across the whole initial-access surface:

| Drop this | What Aegis shows |
|---|---|
| a malicious **PDF** | `/JavaScript` + `/OpenAction` + `/Launch` → auto-execute finding |
| a macro **.docm / .xlsm** | AutoOpen macro + shell/download primitives + remote template |
| a **PowerShell / .js** dropper | download-and-execute pattern, obfuscation score, `-enc` |
| a **.lnk** | recovered command-line args → `powershell -enc …` |
| an **HTML** file | HTML-smuggling score (encoded blob + in-browser download) |
| an **ISO** | Mark-of-the-Web-bypass container carrying a `.lnk`/`.exe` lure |
| a Windows **PE** / Linux **ELF** / **Mach-O** | packer/RWX/imphash / RWX segments / arch + signing |

Every one produces evidence-first findings, IOCs, the visual panels, ATT&CK mapping, and exportable rules.

---

## 3. See it actually run (real detonation)

- **Android:** `SANDBOX_BACKEND=avd` + an AVD named `aegis-avd` → upload an APK with Profile **Dynamic**. Boots a headless emulator, **enforces airplane mode and verifies no egress**, runs under Frida, captures real SMS/network/exec behaviour, then wipes.
- **Linux/ELF:** start Docker, `SANDBOX_BACKEND=docker` → detonates in a locked-down container (`--network none`, cap-drop, read-only) with strace. Add `DOCKER_SINKHOLE=true` to let it *attempt* C2 and capture every domain/URL it reaches — with zero real egress.

---

## 4. The 45-second elevator pitch

> Most malware reaches a victim as a wedding invite, an invoice PDF, a résumé with a macro, or a shortcut in a ZIP — and by the time antivirus has a signature, the campaign's over. **Aegis Sandbox** is an AI-assisted analysis platform that triages a sample across every major format — executables, documents, scripts, and the shortcuts/HTML/ISO files used to deliver them — and tells you *what it does*, with evidence.
>
> We tested it on a spyware APK that **all 64 VirusTotal engines rated clean**. Aegis flagged it in seconds: hard-coded command-and-control, a Telegram exfiltration channel, silent data staging — mapped to MITRE ATT&CK, with a one-click report and YARA/Sigma rules ready for your tooling. For samples it can't judge from structure alone, it **detonates them in a real, network-isolated sandbox** and watches the behaviour.
>
> It's not a magic "malicious/clean" button — nothing is. It's decision-support that catches what signature AV misses and cuts an analyst's triage from hours to minutes.

---

## 5. How it stays safe (say this if asked)

- **Static analysis is parse-only** — the sample is read, never executed.
- **Dynamic detonation runs the sample only inside a disposable, network-isolated guest** (Android emulator in airplane mode, or a Docker container with `--network none`), which is **verified offline before staging** and torn down after. The host is never touched; live malware never runs on it.
- **Secrets and samples stay in git-ignored files** and are never committed.

---

## 6. Honest framing (don't oversell — it's more credible)

- Aegis raises catch-rate and cuts triage time; it does **not** promise to catch *every* sample — that's undecidable in general, and every vendor has false negatives.
- Detonation currently covers **Android + Linux**; Windows PE and macOS are static-only today (Windows has an honest, unconfigured stub rather than fake telemetry).
- Findings are **heuristic and evidence-linked** — built for an analyst to review, not to auto-block.

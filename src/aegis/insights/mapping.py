"""Static mapping tables for the insight/visualization layer.

Kept data-driven and separate from the scoring logic so the mappings are easy to audit
and extend. ``ATTACK_MAP`` links our engine's stable indicator ids to MITRE ATT&CK
techniques (Mobile for APK/DEX, Enterprise for PE/ELF); ``PERMISSION_CATEGORIES`` groups
Android permissions into risk-bearing buckets for the heatmap.
"""

from __future__ import annotations

# ── Android permission grouping (heatmap) ────────────────────────────────────
# Order matters: categories are checked top-to-bottom, first match wins. Names are
# matched against the permission with the ``android.permission.`` prefix stripped.

PERMISSION_CATEGORIES: list[dict] = [
    {"key": "sms", "label": "SMS / Messaging", "risk": "high",
     "match": ["SEND_SMS", "RECEIVE_SMS", "READ_SMS", "WRITE_SMS", "RECEIVE_MMS",
               "RECEIVE_WAP_PUSH", "BROADCAST_SMS"]},
    {"key": "telephony", "label": "Phone / Telephony", "risk": "high",
     "match": ["CALL_PHONE", "READ_CALL_LOG", "WRITE_CALL_LOG", "PROCESS_OUTGOING_CALLS",
               "ANSWER_PHONE_CALLS", "READ_PHONE_STATE", "READ_PHONE_NUMBERS",
               "MODIFY_PHONE_STATE", "CALL_PRIVILEGED"]},
    {"key": "location", "label": "Location", "risk": "high",
     "match": ["ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
               "ACCESS_BACKGROUND_LOCATION", "ACCESS_MEDIA_LOCATION"]},
    {"key": "camera_mic", "label": "Camera / Microphone", "risk": "high",
     "match": ["CAMERA", "RECORD_AUDIO", "CAPTURE_AUDIO_OUTPUT"]},
    {"key": "contacts", "label": "Contacts / Accounts", "risk": "medium",
     "match": ["READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS", "READ_CALENDAR",
               "WRITE_CALENDAR", "AUTHENTICATE_ACCOUNTS", "USE_CREDENTIALS",
               "MANAGE_ACCOUNTS"]},
    {"key": "admin_a11y", "label": "Device Admin / Accessibility", "risk": "critical",
     "match": ["BIND_DEVICE_ADMIN", "BIND_ACCESSIBILITY_SERVICE", "WRITE_SECURE_SETTINGS",
               "WRITE_SETTINGS", "MANAGE_DEVICE_ADMINS", "STATUS_BAR"]},
    {"key": "overlay", "label": "Screen Overlay", "risk": "high",
     "match": ["SYSTEM_ALERT_WINDOW", "ACTION_MANAGE_OVERLAY_PERMISSION"]},
    {"key": "packages", "label": "Install / Manage Apps", "risk": "high",
     "match": ["REQUEST_INSTALL_PACKAGES", "INSTALL_PACKAGES", "DELETE_PACKAGES",
               "REQUEST_DELETE_PACKAGES", "QUERY_ALL_PACKAGES"]},
    {"key": "storage", "label": "Storage / Files", "risk": "medium",
     "match": ["READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
               "MANAGE_EXTERNAL_STORAGE", "READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO",
               "READ_MEDIA_AUDIO"]},
    {"key": "persistence", "label": "Persistence / Background", "risk": "medium",
     "match": ["RECEIVE_BOOT_COMPLETED", "FOREGROUND_SERVICE", "WAKE_LOCK",
               "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS", "SCHEDULE_EXACT_ALARM",
               "DISABLE_KEYGUARD", "REORDER_TASKS", "GET_TASKS"]},
    {"key": "network", "label": "Network", "risk": "low",
     "match": ["INTERNET", "ACCESS_NETWORK_STATE", "ACCESS_WIFI_STATE",
               "CHANGE_WIFI_STATE", "CHANGE_NETWORK_STATE", "NEARBY_WIFI_DEVICES",
               "BLUETOOTH", "BLUETOOTH_CONNECT", "BLUETOOTH_SCAN"]},
]

# Permissions Android itself classes as dangerous / signature-special that most warrant
# highlighting even when their category risk is otherwise moderate.
DANGEROUS_PERMISSIONS: set[str] = {
    "SEND_SMS", "RECEIVE_SMS", "READ_SMS", "RECEIVE_MMS", "RECEIVE_WAP_PUSH",
    "READ_CALL_LOG", "WRITE_CALL_LOG", "PROCESS_OUTGOING_CALLS", "CALL_PHONE",
    "ANSWER_PHONE_CALLS", "READ_PHONE_STATE", "READ_PHONE_NUMBERS",
    "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
    "CAMERA", "RECORD_AUDIO", "READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS",
    "READ_CALENDAR", "WRITE_CALENDAR", "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
    "MANAGE_EXTERNAL_STORAGE", "SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES",
    "BIND_ACCESSIBILITY_SERVICE", "BIND_DEVICE_ADMIN", "WRITE_SECURE_SETTINGS",
    "READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO", "READ_MEDIA_AUDIO",
}

RISK_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# ── Indicator id -> MITRE ATT&CK technique(s) ────────────────────────────────
# Each value: list of (tactic, technique_id, technique_name). Mobile matrix for the
# apk.*/dyn.*/archive.*/net.* rules; Enterprise matrix for pe.*/elf.*.

ATTACK_MAP: dict[str, list[tuple[str, str, str]]] = {
    # Android — static
    "apk.sms_capability": [
        ("Collection", "T1636.004", "Protected User Data: SMS Messages"),
        ("Impact", "T1582", "SMS Control")],
    "apk.accessibility_service": [
        ("Privilege Escalation", "T1626", "Abuse Elevation Control Mechanism"),
        ("Collection", "T1417.001", "Input Capture: Keylogging")],
    "apk.overlay_plus_accessibility": [
        ("Credential Access", "T1417.002", "Input Capture: GUI Input Capture")],
    "apk.device_admin": [
        ("Privilege Escalation", "T1626.001", "Device Administrator Permissions")],
    "apk.dynamic_code_loading": [
        ("Defense Evasion", "T1407", "Download New Code at Runtime")],
    "apk.request_install_packages": [
        ("Defense Evasion", "T1407", "Download New Code at Runtime")],
    "apk.excessive_permissions": [
        ("Discovery", "T1424", "Process Discovery")],
    # Android — dynamic (observed at runtime)
    "dyn.sms_sent": [("Impact", "T1582", "SMS Control")],
    "dyn.runtime_c2": [
        ("Command and Control", "T1437.001", "Application Layer Protocol: Web Protocols")],
    "dyn.c2_beacon": [
        ("Command and Control", "T1437.001", "Application Layer Protocol: Web Protocols")],
    "dyn.dynamic_code_load": [
        ("Defense Evasion", "T1407", "Download New Code at Runtime")],
    "dyn.dropper_chain": [
        ("Defense Evasion", "T1407", "Download New Code at Runtime")],
    "dyn.command_exec": [
        ("Execution", "T1623.001", "Command and Scripting Interpreter: Unix Shell")],
    "dyn.identifier_harvest": [
        ("Discovery", "T1426", "System Information Discovery"),
        ("Collection", "T1409", "Stored Application Data")],
    "dyn.location_access": [("Collection", "T1430", "Location Tracking")],
    "dyn.media_capture": [
        ("Collection", "T1429", "Audio Capture"),
        ("Collection", "T1512", "Video Capture")],
    "dyn.accessibility_active": [
        ("Privilege Escalation", "T1626", "Abuse Elevation Control Mechanism")],
    # Archive / correlation
    "archive.spyware_capabilities": [
        ("Collection", "T1636", "Protected User Data")],
    "archive.embedded_apk": [
        ("Defense Evasion", "T1406", "Obfuscated Files or Information")],
    "net.hardcoded_ip_c2": [
        ("Command and Control", "T1437.001", "Application Layer Protocol: Web Protocols")],
    "net.hardcoded_ip": [
        ("Command and Control", "T1437", "Application Layer Protocol")],
    "net.telegram_channel": [
        ("Command and Control", "T1437.001", "Application Layer Protocol: Web Protocols"),
        ("Exfiltration", "T1639", "Exfiltration Over Alternative Protocol")],
    "apk.network_without_internet_permission": [
        ("Defense Evasion", "T1406", "Obfuscated Files or Information")],
    # PE / ELF — Enterprise
    "pe.packer_section": [("Defense Evasion", "T1027.002", "Software Packing")],
    "pe.high_entropy_code": [("Defense Evasion", "T1027.002", "Software Packing")],
    "elf.high_entropy_code": [("Defense Evasion", "T1027.002", "Software Packing")],
    "pe.suspicious_imports": [("Execution", "T1106", "Native API")],
    "elf.suspicious_imports": [("Execution", "T1106", "Native API")],
    "pe.rwx_section": [("Defense Evasion", "T1055", "Process Injection")],
    "elf.rwx_segment": [("Defense Evasion", "T1055", "Process Injection")],
    "pe.tls_callbacks": [("Defense Evasion", "T1622", "Debugger Evasion")],
    "pe.future_timestamp": [("Defense Evasion", "T1070.006", "Indicator Removal: Timestomp")],
    "pe.tiny_import_table": [("Defense Evasion", "T1027", "Obfuscated Files or Information")],
    "elf.stripped": [("Defense Evasion", "T1027", "Obfuscated Files or Information")],
    "elf.rpath_set": [("Hijack Execution Flow", "T1574.006", "Dynamic Linker Hijacking")],
    # PDF
    "pdf.javascript": [("Execution", "T1204.002", "User Execution: Malicious File")],
    "pdf.auto_action": [("Execution", "T1204.002", "User Execution: Malicious File")],
    "pdf.launch_action": [("Execution", "T1204.002", "User Execution: Malicious File")],
    "pdf.embedded_file": [("Defense Evasion", "T1027", "Obfuscated Files or Information")],
    "pdf.exploit_surface": [("Execution", "T1203", "Exploitation for Client Execution")],
    # Office maldocs
    "office.macros_present": [("Execution", "T1204.002", "User Execution: Malicious File")],
    "office.auto_exec_macro": [("Execution", "T1059.005", "Command and Scripting Interpreter: Visual Basic")],
    "office.suspicious_macro": [("Execution", "T1059.005", "Command and Scripting Interpreter: Visual Basic")],
    "office.remote_template": [("Defense Evasion", "T1221", "Template Injection")],
    "office.dde": [("Execution", "T1559.002", "Inter-Process Communication: Dynamic Data Exchange")],
    # Scripts
    "script.download_exec": [
        ("Execution", "T1059.001", "Command and Scripting Interpreter: PowerShell"),
        ("Command and Control", "T1105", "Ingress Tool Transfer")],
    "script.suspicious_api": [("Execution", "T1059", "Command and Scripting Interpreter")],
    "script.encoded_command": [("Defense Evasion", "T1027.010", "Command Obfuscation")],
    "script.obfuscated": [("Defense Evasion", "T1027", "Obfuscated Files or Information")],
    # Mach-O
    "macho.encrypted": [("Defense Evasion", "T1027.002", "Software Packing")],
    "macho.rpath_set": [("Hijack Execution Flow", "T1574.004", "Dylib Hijacking")],
    # LNK
    "lnk.command_execution": [
        ("Execution", "T1059.001", "Command and Scripting Interpreter: PowerShell"),
        ("Initial Access", "T1566.001", "Spearphishing Attachment")],
    "lnk.interpreter": [("Execution", "T1059", "Command and Scripting Interpreter")],
    # RTF
    "rtf.equation_exploit": [("Execution", "T1203", "Exploitation for Client Execution")],
    "rtf.embedded_executable": [("Defense Evasion", "T1027", "Obfuscated Files or Information")],
    "rtf.ole_object": [("Execution", "T1204.002", "User Execution: Malicious File")],
    # HTML smuggling
    "html.smuggling": [("Defense Evasion", "T1027.006", "HTML Smuggling")],
    "html.suspicious_script": [("Defense Evasion", "T1027.006", "HTML Smuggling")],
    # JAR
    "jar.command_exec": [("Execution", "T1059", "Command and Scripting Interpreter")],
    "jar.dynamic_load": [("Defense Evasion", "T1027", "Obfuscated Files or Information")],
    # ISO container
    "iso.motw_bypass_payload": [("Defense Evasion", "T1553.005", "Mark-of-the-Web Bypass")],
    "iso.container": [("Defense Evasion", "T1553.005", "Mark-of-the-Web Bypass")],
}

# Canonical tactic ordering for the matrix columns (kill-chain left-to-right).
TACTIC_ORDER = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Collection",
    "Command and Control", "Exfiltration", "Impact", "Hijack Execution Flow",
]

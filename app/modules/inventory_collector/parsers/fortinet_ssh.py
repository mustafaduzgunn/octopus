"""
parsers/fortinet_ssh.py
────────────────────────
FortiAnalyzer / FortiManager / FortiAuthenticator /
FortiSandbox / FortiClientEMS envanter parser'ı.

Komut: get system status
Tüm bu cihazlar benzer bir çıktı formatı kullanır:

  Platform Type         : FortiAnalyzer-3000G
  Platform Full Name    : FortiAnalyzer-3000G
  Version               : v7.4.2-build2397 240209 (GA)
  Serial Number         : FAZ-VM0000000001
  BIOS version          : 04000025
  Hostname              : FAZ-PRIMARY
  High Availability     : Disabled
  System time           : Mon Feb  9 10:23:45 2024
  Last reboot reason    : Software upgrade
"""

import re
from datetime import datetime


# Cihaz tipine göre marka adı
_BRAND_MAP = {
    "fortianalyzer": "Fortinet FortiAnalyzer",
    "fortimanager":  "Fortinet FortiManager",
    "fortiauthenticator": "Fortinet FortiAuthenticator",
    "fortisandbox":  "Fortinet FortiSandbox",
    "forticlientems": "Fortinet FortiClient EMS",
    "fortiems":       "Fortinet FortiClient EMS",
}


def parse_fortinet_ssh(status_output: str, device_type: str = "") -> dict:
    """
    status_output : 'get system status' komutunun çıktısı
    device_type   : inventory.json'daki device_type değeri (marka adı için)
    """
    dt   = device_type.lower()
    brand = next((v for k, v in _BRAND_MAP.items() if k in dt), "Fortinet")
    data: dict = {"brand": brand}

    def _field(pattern: str) -> str | None:
        m = re.search(pattern, status_output, re.IGNORECASE | re.MULTILINE)
        return m.group(1).strip() if m else None

    # ── Model ──────────────────────────────────────────────
    # "Platform Full Name    : FortiAnalyzer-3000G"  (öncelikli)
    # "Platform Type         : FortiAnalyzer-3000G"
    data["model"] = (
        _field(r"Platform\s+Full\s+Name\s*:\s*(.+)")
        or _field(r"Platform\s+Type\s*:\s*(.+)")
    )

    # ── Hostname ───────────────────────────────────────────
    data["hostname"] = _field(r"Hostname\s*:\s*(.+)")

    # ── Serial number ──────────────────────────────────────
    data["serial_no"] = _field(r"Serial\s+Number\s*:\s*(\S+)")

    # ── Software version ───────────────────────────────────
    # "Version  : v7.4.2-build2397 240209 (GA)"
    ver_raw = _field(r"^Version\s*:\s*(.+)")
    if ver_raw:
        # "v7.4.2-build2397 ..." → "7.4.2"
        ver_match = re.match(r"v?([\d\.]+)", ver_raw)
        data["software_version"] = ver_match.group(1) if ver_match else ver_raw.split()[0]
        # Build numarası
        build_match = re.search(r"build(\d+)", ver_raw, re.IGNORECASE)
        data["build"] = build_match.group(1) if build_match else None
    else:
        data["software_version"] = None
        data["build"] = None

    # ── HA bilgisi ─────────────────────────────────────────
    ha_raw = _field(r"High\s+Availability\s*:\s*(.+)")
    data["ha_mode"] = ha_raw if ha_raw and ha_raw.lower() != "disabled" else None

    # ── Son yeniden başlatma sebebi ────────────────────────
    data["last_reboot_reason"] = _field(r"Last\s+reboot\s+reason\s*:\s*(.+)")

    # ── BIOS version ───────────────────────────────────────
    data["bios_version"] = _field(r"BIOS\s+[Vv]ersion\s*:\s*(\S+)")

    return data
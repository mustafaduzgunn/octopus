"""
parsers/extreme.py
──────────────────
Extreme Networks ExtremeXOS envanter parser'ı.

Komutlar:
  show switch   → model, hostname, uptime, versiyon, serial
  show version  → detayli versiyon bilgisi (extra_out)
"""

import re


def parse_extreme(switch_output: str, version_output: str = "") -> dict:
    data: dict = {"brand": "Extreme Networks"}

    # ── Model ─────────────────────────────────────────────
    # "System Type:      X440G2-24p-10G4"
    m = re.search(r"System Type:\s+(\S+)", switch_output, re.IGNORECASE)
    if not m:
        # "Switch          : 800616-00-22 2129G-00558 Rev 22 ..." satiri
        m = re.search(r"^Switch\s+:.*?(\w{6}-\w{2}-\w+)", switch_output, re.MULTILINE)
    data["model"] = m.group(1).strip() if m else None

    # ── Hostname ───────────────────────────────────────────
    # "SysName:          MCN_UPS_SW"
    m = re.search(r"SysName:\s+(\S+)", switch_output, re.IGNORECASE)
    data["hostname"] = m.group(1).strip() if m else None

    # ── Software version ───────────────────────────────────
    # "Primary ver:      30.7.1.1"  veya  "ExtremeXOS version 30.7.1.1"
    m = re.search(r"Primary ver:\s+(\S+)", switch_output, re.IGNORECASE)
    if not m:
        m = re.search(r"ExtremeXOS version ([\d\.]+)", version_output or switch_output, re.IGNORECASE)
    data["software_version"] = m.group(1).strip() if m else None

    # Patch
    m = re.search(r"patch[\w\-]+", switch_output, re.IGNORECASE)
    data["patch"] = m.group(0).strip() if m else None

    # ── Serial number ──────────────────────────────────────
    # "Switch          : 800616-00-22 2129G-00558 Rev 22 ..."
    # show switch'te serial yok; show version (extra_out) icinde 2. alan serial'dir
    combined = (version_output or "") + "\n" + switch_output
    m = re.search(r"^Switch\s+:\s+\S+\s+(\S+)", combined, re.MULTILINE)
    data["serial_no"] = m.group(1).strip() if m else None

    # ── Uptime ─────────────────────────────────────────────
    # "System UpTime:    17 days 21 hours 26 minutes 22 seconds"
    m = re.search(r"System UpTime:\s+(.+)", switch_output, re.IGNORECASE)
    data["uptime"] = m.group(1).strip() if m else None

    # ── Location / Contact ────────────────────────────────
    m = re.search(r"SysLocation:\s+(.+)", switch_output, re.IGNORECASE)
    data["location"] = m.group(1).strip() if m else None

    m = re.search(r"SysContact:\s+(.+)", switch_output, re.IGNORECASE)
    data["contact"] = m.group(1).strip() if m else None

    # ── MAC address ───────────────────────────────────────
    m = re.search(r"System MAC:\s+([0-9A-Fa-f:]+)", switch_output, re.IGNORECASE)
    data["mac_address"] = m.group(1).strip() if m else None

    return data
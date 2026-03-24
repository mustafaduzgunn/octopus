"""
parsers/ruijie.py
─────────────────
Ruijie Networks RGOS envanter parser'ı.

Komutlar:
  show version  → model, versiyon, serial, uptime
"""

import re


def parse_ruijie(version_output: str, extra_output: str = "") -> dict:
    data: dict = {"brand": "Ruijie Networks"}

    # ── Model ─────────────────────────────────────────────
    # "System description : Ruijie Full 10G Routing Switch(S6220-48XS6QXS-H) By Ruijie Networks"
    m = re.search(r"System description\s*:\s*.*?\(([^)]+)\)", version_output, re.IGNORECASE)
    if not m:
        # "Slot 1/0 : RG-S6220-48XS6QXS-H"
        m = re.search(r"Slot\s+1/0\s*:\s*([\w\-]+)", version_output, re.IGNORECASE)
    data["model"] = m.group(1).strip() if m else None

    # ── Software version ───────────────────────────────────
    # "System software version : S6220_RGOS 11.0(5)B9P33"
    m = re.search(r"System software version\s*:\s*(.+)", version_output, re.IGNORECASE)
    data["software_version"] = m.group(1).strip() if m else None

    # ── Hardware version ───────────────────────────────────
    m = re.search(r"System hardware version\s*:\s*(\S+)", version_output, re.IGNORECASE)
    data["hardware_version"] = m.group(1).strip() if m else None

    # ── Serial number ──────────────────────────────────────
    # "System serial number    : G1NTAYD101243"
    m = re.search(r"System serial number\s*:\s*(\S+)", version_output, re.IGNORECASE)
    data["serial_no"] = m.group(1).strip() if m else None

    # ── Uptime ─────────────────────────────────────────────
    # "System uptime           : 58:20:19:40"
    m = re.search(r"System uptime\s*:\s*(.+)", version_output, re.IGNORECASE)
    data["uptime"] = m.group(1).strip() if m else None

    # ── Boot version ───────────────────────────────────────
    m = re.search(r"System boot version\s*:\s*(\S+)", version_output, re.IGNORECASE)
    data["boot_version"] = m.group(1).strip() if m else None

    # ── Hostname — prompt'tan ─────────────────────────────
    # "MACUNKOY_VM_RJ#show version" → prompt'tan hostnami al
    m = re.search(r"^(\S+)#", version_output, re.MULTILINE)
    if m and "show" not in m.group(1).lower():
        data["hostname"] = m.group(1).strip()

    # ── Module/Slot bilgisi ───────────────────────────────
    modules = []
    for slot_m in re.finditer(
        r"Slot\s+([\d/]+)\s*:\s*([\w\-]+).*?(?:Serial number\s*:\s*(\S+))?",
        version_output, re.IGNORECASE | re.DOTALL
    ):
        slot_info = {"slot": slot_m.group(1), "model": slot_m.group(2)}
        if slot_m.group(3):
            slot_info["serial"] = slot_m.group(3)
        modules.append(slot_info)
    if modules:
        data["modules"] = modules

    return data
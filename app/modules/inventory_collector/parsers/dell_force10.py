"""
parsers/dell_force10.py
────────────────────────
Dell Force10 (FTOS / Dell EMC Networking OS) envanter parser'ı.

Komutlar:
  show version        → model, sürüm, uptime, serial
  show inventory      → serial (yedek kaynak)
"""

import re


def parse_dell_force10(version_output: str, inventory_output: str = "") -> dict:
    data: dict = {"brand": "Dell Force10"}

    # ── Model ──────────────────────────────────────────────
    # "Dell Force10 Networks Real Time Operating System Software"
    # "System Type: S4148F-ON"
    model_match = re.search(r"System\s+Type\s*:\s*(\S+)", version_output, re.IGNORECASE)
    if not model_match:
        # Eski FTOS: "Dell Force10 Networks S-Series" ilk satırdan
        model_match = re.search(
            r"(?:Dell\s+Force10\s+Networks|Real\s+Time)\s+(\S[\w\-]+)", version_output
        )
    data["model"] = model_match.group(1).strip() if model_match else None

    # ── Software version ───────────────────────────────────
    # "Operating System Version: 9.14(2.0)"
    ver_match = re.search(
        r"(?:Operating\s+System\s+Version|Software\s+Version)\s*:\s*(\S+)",
        version_output,
        re.IGNORECASE,
    )
    if not ver_match:
        # "Version: 2.0.0.6" tarzı
        ver_match = re.search(r"Version\s*:\s*([\d\.]+)", version_output, re.IGNORECASE)
    data["software_version"] = ver_match.group(1).strip() if ver_match else None

    # ── Uptime ─────────────────────────────────────────────
    # "System uptime: 2 days, 14 hours, 30 minutes"
    uptime_match = re.search(r"[Ss]ystem\s+uptime\s*:\s*(.+)", version_output)
    if not uptime_match:
        uptime_match = re.search(r"uptime\s+is\s+(.+)", version_output)
    data["uptime"] = uptime_match.group(1).strip() if uptime_match else None

    # ── Serial number ──────────────────────────────────────
    # show version: "System image: ...\nSerial Number: TW2BGB2"
    serial_match = re.search(r"[Ss]erial\s+[Nn]umber\s*:\s*(\S+)", version_output)
    if not serial_match and inventory_output:
        serial_match = re.search(r"[Ss]erial\s+[Nn]umber\s*:\s*(\S+)", inventory_output)
    data["serial_no"] = serial_match.group(1).strip() if serial_match else None

    # ── Inventory / stack üyeleri (show inventory) ─────────
    # NAME: "Stack unit 1",  DESCR: "... S4148F-ON"
    # PID: S4148F-ON ,  VID: A0 ,  SN: ABCD1234
    stack_members: list[dict] = []
    stack_blocks = re.findall(
        r'NAME:\s*"Stack unit (\d+)".*?PID:\s*(\S+).*?SN:\s*(\S+)',
        inventory_output,
        re.DOTALL | re.IGNORECASE,
    )
    for member_id, pid, sn in stack_blocks:
        stack_members.append({"member": member_id, "model": pid, "serial_number": sn})
    if stack_members:
        data["stack_members"] = stack_members
        # İlk üyeyi ana seri olarak kullan (show version'dan bulunamazsa)
        if not data["serial_no"]:
            data["serial_no"] = stack_members[0]["serial_number"]
        if not data["model"]:
            data["model"] = stack_members[0]["model"]
    else:
        data["stack_members"] = []

    return data

"""
parsers/hp_comware.py
──────────────────────
HP Comware (H3C) envanter parser'ı.

Komutlar:
  display version        → model, sürüm, uptime
  display device manuinfo → serial (slot bazlı)
"""

import re


def parse_hp_comware(version_output: str, manuinfo_output: str = "") -> dict:
    # Marka tespiti: H3C mi HP mi?
    if re.search(r"h3c comware|^h3c\s", version_output, re.IGNORECASE | re.MULTILINE):
        brand = "H3C"
    else:
        brand = "HP/H3C Comware"
    data: dict = {"brand": brand}

    # ── Model ──────────────────────────────────────────────
    # Oncelik 1: "H3C S9820-64H uptime is ..." / "HP 5920AF-24XG uptime is ..."
    model_match = re.search(
        r"^(?:HP|H3C)\s+([\w\-]+)\s+uptime",
        version_output, re.MULTILINE | re.IGNORECASE,
    )
    if not model_match:
        # Oncelik 2: "BOARD TYPE:         S9820-64H"
        model_match = re.search(r"BOARD TYPE:\s+(\S+)", version_output)
    if not model_match:
        # Oncelik 3: "Product name    : HP 5920AF-24XG"
        model_match = re.search(r"[Pp]roduct\s+[Nn]ame\s*:\s*(.+)", version_output)
    if not model_match:
        # Oncelik 4: herhangi bir HP/H3C XXXX referansi
        model_match = re.search(
            r"(?:HP|H3C)\s+([\w\-]+(?:[-\s][\w]+){0,3})",
            version_output, re.IGNORECASE,
        )
    data["model"] = model_match.group(1).strip() if model_match else None

    # ── Software version ───────────────────────────────────
    # "H3C Comware Software, Version 7.1.070, Release 6710"
    # "Comware Software, Version 7.1.070, Release 3506P10"
    # "Software Version 5.20 Release 2208P07"
    ver_match = re.search(
        r"(?:[Ss]oftware\s+)?[Vv]ersion\s+([\d\.]+)",
        version_output,
    )
    data["software_version"] = ver_match.group(1).strip() if ver_match else None

    # Release / Patch bilgisi
    release_match = re.search(r"[Rr]elease\s+(\S+)", version_output)
    data["release"] = release_match.group(1).strip() if release_match else None

    # Patch version (H3C: "Patch Version:      R6710HS15")
    patch_match = re.search(r"Patch\s+[Vv]ersion\s*:\s*(\S+)", version_output)
    data["patch_version"] = patch_match.group(1).strip() if patch_match else None

    # ── Uptime ─────────────────────────────────────────────
    uptime_match = re.search(r"uptime is (.+)", version_output)
    data["uptime"] = uptime_match.group(1).strip() if uptime_match else None

    # ── Serial number (display device manuinfo) ────────────
    # "[Slot1]"
    # "Device serial number    : CN1234A5BC"
    # Önce Slot 1'i dene, bulamazsan ilk serial'i al
    serial: str | None = None

    if manuinfo_output:
        slot1_match = re.search(
            r"\[Slot\s*1\][\s\S]*?[Ss]erial\s+[Nn]umber\s*:\s*(\S+)",
            manuinfo_output,
        )
        if slot1_match:
            serial = slot1_match.group(1).strip()
        else:
            any_serial = re.search(
                r"[Ss]erial\s+[Nn]umber\s*:\s*(\S+)", manuinfo_output
            )
            if any_serial:
                serial = any_serial.group(1).strip()

    # show version içinde serial geçiyorsa (bazı modeller)
    if not serial:
        ver_serial = re.search(
            r"[Ss]erial\s+[Nn]umber\s*:\s*(\S+)", version_output
        )
        if ver_serial:
            serial = ver_serial.group(1).strip()

    data["serial_no"] = serial

    # ── Slot bazlı serial listesi ──────────────────────────
    if manuinfo_output:
        slot_serials: dict[str, str] = {}
        for slot_name, sn in re.findall(
            r"\[(Slot\s*\d+)\][\s\S]*?[Ss]erial\s+[Nn]umber\s*:\s*(\S+)",
            manuinfo_output,
        ):
            slot_serials[slot_name.replace(" ", "").lower()] = sn.strip()
        if slot_serials:
            data["slot_serials"] = slot_serials

    return data
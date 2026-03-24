"""
parsers/huawei.py
──────────────────
Huawei VRP envanter parser'ı.

Komutlar:
  display version              → model, software_version, uptime, patch
  display device elabel brief  → serial_no (NE8000 tablo format)
  display elabel slot X        → serial_no (S-serisi blok format)
  display elabel unit X        → serial_no (eski S5300/S5700 blok format)

Desteklenen cihaz/format kombinasyonları:
  - NE8000 F/M serisi   (VRP 8.x, elabel brief tablo)
  - S6720 / S5700 yeni  (VRP 5.17x, "HUAWEI SXXXX Routing Switch uptime is")
  - S5352 / S5328 eski  (VRP 5.x,  "Quidway SXXXX [Routing Switch] uptime is")
"""

import re


def parse_huawei(version_output: str, elabel_output: str = "") -> dict:
    data: dict = {"brand": "Huawei"}

    # ── Model ─────────────────────────────────────────────
    model = None

    # 1. NE8000: "HUAWEI NetEngine 8000 F1A-8H20Q uptime is"
    m = re.search(
        r"HUAWEI\s+(NetEngine\s+\d+\s+[\w\-]+)\s+uptime",
        version_output, re.IGNORECASE
    )
    if m:
        model = m.group(1).strip()

    # 2. S-serisi yeni: "HUAWEI S6720-26Q-SI-24S-AC Routing Switch uptime is"
    if not model:
        m = re.search(
            r"HUAWEI\s+([\w\-]+)\s+(?:Routing\s+Switch|Router|Switch)\s+uptime",
            version_output, re.IGNORECASE
        )
        if m:
            model = m.group(1).strip()

    # 3. Quidway + tip etiketi: "Quidway S5352C-EI Routing Switch uptime is"
    if not model:
        m = re.search(
            r"Quidway\s+([\w\-]+)\s+(?:Routing\s+Switch|Router|Switch)\s+uptime",
            version_output, re.IGNORECASE
        )
        if m:
            model = m.group(1).strip()

    # 4. Quidway eski (tip etiketi yok): "Quidway S5328C-EI uptime is"
    if not model:
        m = re.search(r"Quidway\s+([\w\-]+)\s+uptime", version_output, re.IGNORECASE)
        if m:
            model = m.group(1).strip()

    # 5. Son çare — eski "Board Type : XXXX" satırı
    if not model:
        m = re.search(r"Board\s+Type\s*:\s*(\S+)", version_output)
        if m:
            model = m.group(1).strip()

    data["model"] = model

    # ── Software version ───────────────────────────────────
    # "VRP (R) software, Version 8.240 (NetEngine 8000 ...)"
    # "VRP (R) Software, Version 5.130 (S5300 ...)"
    m = re.search(r"VRP\s+\(R\)\s+[Ss]oftware,\s+Version\s+([\d\.]+)", version_output)
    if not m:
        m = re.search(r"Version\s+([\d\.]+)\s+\(", version_output)
    data["software_version"] = m.group(1).strip() if m else None

    # ── Patch version ──────────────────────────────────────
    m = re.search(r"Patch\s+Version\s*:\s*(\S+)", version_output, re.IGNORECASE)
    data["patch"] = m.group(1).strip() if m else None

    # ── Uptime ─────────────────────────────────────────────
    # Cihaz uptime'ını al (HUAWEI/Quidway satırından), master slot uptime'ından önce
    m = re.search(
        r"^(?:HUAWEI|Quidway)\s+.+\s+uptime\s+is\s+(.+)",
        version_output, re.MULTILINE | re.IGNORECASE
    )
    if not m:
        m = re.search(r"uptime\s+is\s+(.+)", version_output)
    data["uptime"] = m.group(1).strip() if m else None

    # ── Serial number — elabel çıktısından ────────────────
    serial = None
    if elabel_output:
        # Format A: blok yapı → BarCode=XXXX
        # (display elabel slot X / display elabel unit X çıktısı)
        m = re.search(r"BarCode=(\S+)", elabel_output)
        if m:
            serial = m.group(1).strip()

        # Format B: brief tablo → "IPU/CXP/MPU/LPU  N  BoardType  BarCode  Desc"
        # (display device elabel brief / display elabel brief çıktısı)
        if not serial:
            for line in elabel_output.splitlines():
                cols = line.split()
                if (len(cols) >= 4
                        and cols[0].upper() in ("IPU", "CXP", "MPU", "LPU", "MAIN")
                        and cols[1].isdigit()):
                    # cols[2] = BoardType, cols[3] = BarCode
                    candidate = cols[3]
                    if len(candidate) >= 10 and re.match(r"[A-Z0-9]{10,}", candidate, re.IGNORECASE):
                        serial = candidate
                        break

    data["serial_no"] = serial

    # ── Slot / Unit bazlı serial listesi ──────────────────
    if elabel_output:
        slot_serials: dict[str, str] = {}

        # [Slot_X] blok formatı
        for slot_name, barcode in re.findall(
            r"\[(Slot_\d+)\][\s\S]*?BarCode=(\S+)", elabel_output
        ):
            slot_serials[slot_name.lower()] = barcode

        # [Unit_X] blok formatı (eski S5300/S5700)
        for unit_name, barcode in re.findall(
            r"\[(Unit_\d+)\][\s\S]*?BarCode=(\S+)", elabel_output
        ):
            slot_serials[unit_name.lower()] = barcode

        if slot_serials:
            data["slot_serials"] = slot_serials
            # Blok formatta serial yukarıda BarCode= ile set edildi;
            # set edilmediyse slot listesinden al
            if not data["serial_no"]:
                data["serial_no"] = (
                    slot_serials.get("slot_1")
                    or slot_serials.get("unit_1")
                    or next(iter(slot_serials.values()))
                )

    return data

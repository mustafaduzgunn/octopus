import re


# ---------------------------------------------------------------------------
# Yardımcı: AP çıktısı mı?
# ---------------------------------------------------------------------------
def _is_cisco_ap(version_output: str) -> bool:
    """
    show version çıktısının bir Cisco AP'e ait olup olmadığını tespit eder.
    Ayırt edici işaretler:
      • "Cisco AP Software"
      • "AP Running Image"
      • "802.11 Radio"  (radyo satırı)
    """
    return bool(re.search(
        r"Cisco AP Software|AP Running Image|802\.11 Radio",
        version_output, re.IGNORECASE
    ))


# ---------------------------------------------------------------------------
# Cisco Access Point parser  (C9115 / C9120 / C9130 / AIR-AP vb.)
# ---------------------------------------------------------------------------
def parse_cisco_ap(version_output: str, inventory_output=None) -> dict:
    """
    Cisco AP 'show version' çıktısını ayrıştırır.

    Örnek kaynak:  Cisco Catalyst 9115AXI-E / IOS-XE AP

    Döndürülen alanlar:
        brand, model, serial_no, pcb_serial, software_version,
        hostname, uptime, mac_address, ap_platform, ap_chipset,
        primary_image, backup_image, last_reload_reason
    """
    data: dict = {"brand": "Cisco"}

    # ------------------------------------------------------------------
    # Hostname + Uptime
    # ------------------------------------------------------------------
    m = re.search(r"^(\S+)\s+uptime is (.+)", version_output, re.MULTILINE)
    if m:
        hostname = m.group(1).strip()
        # "cisco" veya genel kelimeler hostname değildir
        if hostname.lower() not in ("cisco", "the", "switch", "router", "ap"):
            data["hostname"] = hostname
        data["uptime"] = m.group(2).strip()

    # ------------------------------------------------------------------
    # Model — önce "Product/Model Number" satırı, yoksa "cisco C9XXX" satırı
    # ------------------------------------------------------------------
    m = re.search(r"Product/Model Number\s*:\s*(\S+)", version_output)
    if m:
        data["model"] = m.group(1).strip()
    else:
        # "cisco C9115AXI-E ARMv8 ..." satırı
        m = re.search(r"^cisco\s+(C\S+)\s+", version_output, re.MULTILINE | re.IGNORECASE)
        if m:
            data["model"] = m.group(1).strip()

    # ------------------------------------------------------------------
    # Serial numarası
    #   Öncelik: Top Assembly Serial Number > Processor board ID > PCB Serial
    # ------------------------------------------------------------------
    m = re.search(r"Top Assembly Serial Number\s*:\s*(\S+)", version_output)
    if m:
        data["serial_no"] = m.group(1).strip()
    else:
        m = re.search(r"Processor board ID\s+(\S+)", version_output)
        if m:
            data["serial_no"] = m.group(1).strip()

    # PCB Serial Number (ikincil — mevcut serial yoksa kullan)
    m = re.search(r"PCB Serial Number\s*:\s*(\S+)", version_output)
    if m:
        pcb = m.group(1).strip()
        data["pcb_serial"] = pcb
        if not data.get("serial_no"):
            data["serial_no"] = pcb

    # ------------------------------------------------------------------
    # Yazılım sürümü — "AP Running Image : 17.9.6.40"
    #   NOT: "BOOTLDR: U-Boot ... Version 0x62" ile karışmamalı
    # ------------------------------------------------------------------
    m = re.search(r"AP Running Image\s*:\s*(\S+)", version_output)
    if m:
        data["software_version"] = m.group(1).strip()
    else:
        # Fallback: "Cisco AP Software, (ap1g7), C9115, RELEASE SOFTWARE" satırındaki
        # "Compiled" sonrası versiyon numarası yerine başka bir pattern dene
        m = re.search(r"Version\s+([\d.]+(?:\.\d+)*)\s", version_output)
        if m:
            data["software_version"] = m.group(1).strip()

    # Primary / Backup boot image
    m = re.search(r"Primary Boot Image\s*:\s*(\S+)", version_output)
    if m:
        data["primary_image"] = m.group(1).strip()

    m = re.search(r"Backup Boot Image\s*:\s*(\S+)", version_output)
    if m:
        data["backup_image"] = m.group(1).strip()

    # ------------------------------------------------------------------
    # MAC adresi
    # ------------------------------------------------------------------
    m = re.search(
        r"Base ethernet MAC Address\s*:\s*([0-9A-Fa-f]{2}(?:[:\-][0-9A-Fa-f]{2}){5})",
        version_output
    )
    if m:
        data["mac_address"] = m.group(1).upper()

    # ------------------------------------------------------------------
    # AP platform / chipset  →  "Cisco AP Software, (ap1g7), C9115, RELEASE SOFTWARE"
    # ------------------------------------------------------------------
    m = re.search(
        r"Cisco AP Software,\s*\(([^)]+)\),\s*([^,\s]+)",
        version_output, re.IGNORECASE
    )
    if m:
        data["ap_chipset"]  = m.group(1).strip()   # ap1g7
        data["ap_platform"] = m.group(2).strip()   # C9115

    # ------------------------------------------------------------------
    # Son yeniden başlatma sebebi
    # ------------------------------------------------------------------
    m = re.search(r"Last reload reason\s*:\s*(.+)", version_output)
    if m:
        data["last_reload_reason"] = m.group(1).strip()

    return data


# ---------------------------------------------------------------------------
# Cisco Switch / Router parser  (mevcut — değiştirilmedi)
# ---------------------------------------------------------------------------
def parse_cisco(version_output, inventory_output=None):

    data = {}
    data["brand"] = "Cisco"

    stack_members = []
    chassis_serial = None
    chassis_model = None

    if inventory_output:

        # -----------------------
        # STACK MEMBER PARSE
        # -----------------------
        stack_pattern = r'NAME: "Switch (\d+)", DESCR: "([^"]+)"\nPID: ([^,]+).*?SN: (\S+)'
        stack_matches = re.findall(stack_pattern, inventory_output, re.MULTILINE)

        for match in stack_matches:
            stack_members.append({
                "member": match[0],
                "model": match[2].strip(),
                "serial_number": match[3].strip()
            })

        # -----------------------
        # CHASSIS PARSE (Router / Standalone)
        # -----------------------
        chassis_pattern = r'NAME: "Chassis".*?\nPID: ([^,]+).*?SN: (\S+)'
        chassis_match = re.search(chassis_pattern, inventory_output, re.MULTILINE)

        if chassis_match:
            chassis_model = chassis_match.group(1).strip()
            chassis_serial = chassis_match.group(2).strip()

    # Stack varsa onu kullan
    if stack_members:
        data["stack_members"] = stack_members
        data["serial_no"] = stack_members[0]["serial_number"]
        data["model"] = stack_members[0]["model"]
    else:
        data["stack_members"] = []
        data["serial_no"] = chassis_serial
        data["model"] = chassis_model

    # -----------------------
    # show version FALLBACK — show inventory bos/yetersiz geldiyse
    # Oncelik sirasi: 1) Model number satiri  2) cisco XXXX processor  3) Switch tablosu
    # -----------------------
    if not data.get("model"):
        m = re.search(r"Model number\s*:\s*(\S+)", version_output, re.IGNORECASE)
        if not m:
            m = re.search(r"^cisco\s+([\w\-]+)\s+\(", version_output, re.MULTILINE | re.IGNORECASE)
        if not m:
            m = re.search(r"^\*\s+\d+\s+\d+\s+([\w\-]+)\s+", version_output, re.MULTILINE)
        if m:
            data["model"] = m.group(1).strip()

    # Serial fallback — show inventory'den gelemediyse show version'dan al
    if not data.get("serial_no"):
        m = re.search(r"System serial number\s*:\s*(\S+)", version_output, re.IGNORECASE)
        if not m:
            m = re.search(r"Processor board ID\s+(\S+)", version_output)
        if m:
            data["serial_no"] = m.group(1).strip()

    # -----------------------
    # HOSTNAME PARSE  (9200/9300/9500 + IOS + NX-OS)
    # -----------------------
    _HOSTNAME_BLACKLIST = {"cisco", "the", "switch", "router", "kernel"}

    hostname = None

    # 1. Once NX-OS "Device name: HOSTNAME" satiri - en guvenilir kaynak
    m = re.search(r"Device name:\s*(\S+)", version_output, re.IGNORECASE)
    if m:
        hostname = m.group(1).strip()

    # 2. IOS/IOS-XE: "HOSTNAME uptime is ..." - "Kernel" satiri haric
    if not hostname:
        uptime_line = re.search(
            r"^(?!Kernel\b)(\S+)\s+uptime is (.+)",
            version_output, re.MULTILINE | re.IGNORECASE
        )
        if uptime_line:
            hostname = uptime_line.group(1).strip()
            data["uptime"] = uptime_line.group(2).strip()

    # uptime degerini ayrica cek (NX-OS: "Kernel uptime is ...")
    uptime_match = re.search(r"(?:Kernel\s+)?uptime is (.+)", version_output, re.IGNORECASE)
    if uptime_match and not data.get("uptime"):
        data["uptime"] = uptime_match.group(1).strip()

    # Blacklist kontrolu - marka adi veya sistem kelimesi hostname olamaz
    if hostname and hostname.lower() in _HOSTNAME_BLACKLIST:
        hostname = None

    if hostname:
        data["hostname"] = hostname

    # -----------------------
    # SOFTWARE VERSION
    # -----------------------
    version_match = re.search(r"Version (\S+),", version_output)
    data["software_version"] = version_match.group(1) if version_match else None

    return data
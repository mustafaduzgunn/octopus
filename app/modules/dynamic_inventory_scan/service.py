"""
app/modules/network_scanner/service.py
───────────────────────────────────────
Ağ keşif motoru.

Akış (her IP için):
  1. TCP ping / ICMP ping  → cihaz ayakta mı?
  2. Inventory kontrolü   → IP zaten kayıtlıysa atla
  3. Port tarama          → 22, 80, 443, 3389 (paralel socket)
  4. ARP / MAC            → gateway FortiGate REST API'den ARP tablosu
  5. MAC Vendor           → yerel OUI tablosu + macvendors.com API fallback
  6. SSH deneme           → port 22 açıksa vault'taki tüm credential çiftleri denenir
  7. Cihaz tipi           → SSH başarılıysa komut çıktısından tespit
  8. Inventory kayıt      → başarılı SSH sonrası inventory.json'a eklenir
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any

import paramiko
import requests
import urllib3

from . import mac_vendor

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

_BASE          = Path(__file__).parent.parent.parent
DATA_DIR       = _BASE / "data"
INVENTORY_PATH = DATA_DIR / "inventory.json"

# Taranacak portlar
SCAN_PORTS = [22, 80, 443, 3389]

# TCP bağlantı timeout (saniye)
CONNECT_TIMEOUT = 0.5

# Paralel IP tarama worker sayısı
HOST_WORKERS = 10

# SSH deneme timeout
SSH_TIMEOUT = 5

# Netmiko ile cihaz tipi tespiti için kullanılan komutlar
# Her komutun ciktisi _classify_device_type ile rafine edilir
_DETECT_CMDS = [
    ("show version",     "cisco_ios"),
    ("display version",  "huawei"),
    ("get system status","fortigate"),
    ("show switch",      "extreme_exos"),
]


def _classify_device_type(output: str, initial_type: str) -> str:
    """
    Ham komut ciktisini analiz ederek daha dogru bir device_type dondurur.
    Donus degerleri Netmiko platform isimlerine uygun olmalidir.
    """
    out_lower = output.lower()

    # H3C Comware — "h3c_comware" (Netmiko tipi)
    if "h3c comware" in out_lower or (
        "comware" in out_lower and re.search(r"h3c\s+[a-z]\d", output, re.IGNORECASE)
    ):
        return "h3c_comware"

    # ExtremeXOS — "extreme_exos" (Netmiko tipi)
    if ("extremexos" in out_lower or "extreme networks" in out_lower
            or "system type:" in out_lower or "sysname:" in out_lower
            or re.search(r"primary ver:\s+\d+\.\d+", output, re.IGNORECASE)):
        return "extreme_exos"

    # Ruijie RGOS — "ruijie_os" (Netmiko tipi)
    if "ruijie" in out_lower or "rgos" in out_lower:
        return "ruijie_os"

    # NX-OS (Nexus) — "cisco_nxos" (Netmiko tipi)
    if "nx-os" in out_lower or "nxos" in out_lower:
        return "cisco_nxos"

    return initial_type


# ─────────────────────────────────────────────────────────
# Yardımcılar
# ─────────────────────────────────────────────────────────

def _load_inventory() -> list[dict]:
    if not INVENTORY_PATH.exists():
        return []
    with open(INVENTORY_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def _save_inventory(inventory: list[dict]) -> None:
    with open(INVENTORY_PATH, "w", encoding="utf-8") as fh:
        json.dump(inventory, fh, indent=2, ensure_ascii=False)


def _normalize_mac(mac: str) -> str:
    """MAC adresini standart aa:bb:cc:dd:ee:ff formatına dönüştürür."""
    if not mac or mac in ("N/A", ""):
        return ""
    # Farklı ayraçları kaldır → 12 karakter hex → standart format
    raw = re.sub(r"[:\-\.]", "", mac).lower()
    if len(raw) != 12 or not re.fullmatch(r"[0-9a-f]{12}", raw):
        return ""
    return ":".join(raw[i:i+2] for i in range(0, 12, 2))


def _inventory_by_mac(inventory: list[dict]) -> dict[str, dict]:
    """MAC → cihaz kaydı haritası döndürür."""
    result: dict[str, dict] = {}
    for d in inventory:
        mac = _normalize_mac(d.get("mac_address", ""))
        if mac:
            result[mac] = d
    return result


def _inventory_by_serial(inventory: list[dict]) -> dict[str, dict]:
    """Serial No → cihaz kaydı haritası döndürür."""
    result: dict[str, dict] = {}
    for d in inventory:
        sn = (d.get("serial_no") or "").strip().upper()
        if sn and sn not in ("N/A", "UNKNOWN", ""):
            result[sn] = d
    return result


def _inventory_ips(inventory: list[dict]) -> set[str]:
    """Primary IP + additional_ips alanindaki tum IP'leri dondurur."""
    ips: set[str] = set()
    for d in inventory:
        if d.get("ip"):
            ips.add(d["ip"])
        for extra in d.get("additional_ips", []):
            if extra:
                ips.add(extra)
    return ips


# ─────────────────────────────────────────────────────────
# Exclude listesi
# ─────────────────────────────────────────────────────────

EXCLUDE_PATH = DATA_DIR / "exclude.json"


def load_exclude() -> list[dict]:
    """
    exclude.json dosyasını yükler.

    Kayıt formatı:
        {
          "ip":          "10.1.2.3",        # zorunlu
          "description": "ISP modem",        # opsiyonel
          "added_at":    "2025-01-01 12:00"  # otomatik
        }
    """
    if not EXCLUDE_PATH.exists():
        return []
    with open(EXCLUDE_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def save_exclude(entries: list[dict]) -> None:
    with open(EXCLUDE_PATH, "w", encoding="utf-8") as fh:
        json.dump(entries, fh, indent=2, ensure_ascii=False)


def excluded_ips() -> set[str]:
    """Exclude listesindeki tüm IP'leri set olarak döndürür."""
    return {e["ip"] for e in load_exclude() if e.get("ip")}


def _tcp_ping(ip: str, ports: tuple[int, ...] | list[int] = (22, 80, 443)) -> bool:
    """Verilen portlardan birine TCP bağlantısı kurulabiliyor mu?"""
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT):
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
    return False


def _icmp_ping(ip: str) -> bool:
    """Sistem ping komutunu çağırarak ICMP yanıtı kontrol eder."""
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
        )
        return result.returncode == 0
    except Exception:
        return False


def is_alive(ip: str) -> bool:
    """TCP ping veya ICMP ile cihazın ayakta olup olmadığını kontrol eder."""
    return _tcp_ping(ip, [22, 80, 443, 8080, 8443]) or _icmp_ping(ip)


def scan_ports(ip: str) -> list[int]:
    """SCAN_PORTS listesindeki portları sırayla tarar, açık olanları döndürür."""
    open_ports: list[int] = []
    for port in SCAN_PORTS:
        try:
            with socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT):
                open_ports.append(port)
        except Exception:
            pass
    return sorted(open_ports)


# ─────────────────────────────────────────────────────────
# ARP / MAC tespiti — tüm FortiGate'ler sorgulanır
# ─────────────────────────────────────────────────────────

# Firewall hostname'leri — inventory'de bu isimler kayıtlı
_FIREWALL_HOSTNAMES = {
    "trsatfw.turksat.com.tr",
    "kamufw.turksat.com.tr",
    "edkfw.turksat.com.tr",
    "macunkoyfw.turksat.com.tr",
    "testfw.turksat.com.tr",
}

# ARP tablosu önbelleği: {fortigate_ip → {target_ip → mac}}
# Aynı tarama oturumunda her FW'ye tek istek gönderilir
_arp_cache: dict[str, dict[str, str]] = {}
_arp_cache_lock = __import__("threading").Lock()
_inventory_write_lock = __import__("threading").Lock()


def _get_all_fortigates(inventory: list[dict]) -> list[dict]:
    """
    Inventory'den tüm FortiGate firewall cihazlarını döndürür.
    Önce _FIREWALL_HOSTNAMES ile eşleşenleri, sonra diğer fortigate'leri alır.
    """
    firewalls: list[dict] = []
    others:    list[dict] = []

    for device in inventory:
        dt = device.get("device_type", "").lower()
        if "fortigate" not in dt and "fortinet" not in dt:
            continue
        if device.get("ip", "") in _FIREWALL_HOSTNAMES:
            firewalls.append(device)
        else:
            others.append(device)

    return firewalls + others


def _ping_via_fortigate(
    session: requests.Session,
    base_url: str,
    params: dict,
    target_ip: str,
) -> None:
    """
    FortiGate REST API üzerinden hedef IP'ye ping gönderir.
    ARP tablosunu doldurmak için kullanılır; sonuç dikkate alınmaz.
    """
    try:
        session.post(
            f"{base_url}/api/v2/monitor/system/ping",
            json={"target": target_ip, "count": 2, "timeout": 1},
            params=params,
            timeout=8,
        )
    except Exception:
        pass


def _fetch_arp_table(
    fgt_ip: str,
    port: int,
    credentials: dict,
    ping_target: str = "",
) -> dict[str, str]:
    """
    FortiGate REST API'den ARP tablosunu çeker.
    ping_target verilmişse önce o IP'ye ping atar (ARP'ı tetiklemek için),
    sonra ARP tablosunu sorgular.
    {ip → mac} dict'i döndürür.
    """
    api_token = credentials.get("api_token", "")
    username  = credentials.get("username", "")
    password  = credentials.get("password", "")
    base_url  = f"https://{fgt_ip}:{port}"

    try:
        session = requests.Session()
        session.verify = False

        if api_token:
            session.headers["Authorization"] = f"Bearer {api_token}"
            params: dict = {"access_token": api_token}
        else:
            r = session.post(
                f"{base_url}/logincheck",
                data={"username": username, "secretkey": password},
                timeout=10,
            )
            r.raise_for_status()
            csrf = r.cookies.get("ccsrftoken", "").strip('"')
            if csrf:
                session.headers["X-CSRFTOKEN"] = csrf
            params = {}

        # Ping → ARP tablosunu doldur
        if ping_target:
            _ping_via_fortigate(session, base_url, params, ping_target)

        resp = session.get(
            f"{base_url}/api/v2/monitor/network/arp",
            params=params,
            timeout=15,
        )
        session.close()

        if not resp.ok:
            logger.debug("FortiGate ARP sorgusu başarısız (%s): HTTP %s",
                         fgt_ip, resp.status_code)
            return {}

        entries = resp.json().get("results", [])
        table = {e["ip"]: e.get("mac", "") for e in entries if e.get("ip")}
        logger.debug("FortiGate %s — %d ARP kaydı alındı", fgt_ip, len(table))
        return table

    except Exception as exc:
        logger.debug("FortiGate ARP hatası (%s): %s", fgt_ip, exc)
        return {}


def _get_cached_arp(fgt_device: dict, all_credentials: dict) -> dict[str, str]:
    """ARP tablosunu önbellekten döndürür; yoksa çekip önbelleğe yazar."""
    fgt_ip = fgt_device["ip"]
    with _arp_cache_lock:
        if fgt_ip in _arp_cache:
            return _arp_cache[fgt_ip]

    cred_id = fgt_device.get("credential_id", "")
    if not cred_id or cred_id not in all_credentials:
        return {}

    # İlk kez çekiliyor — ping_target olmadan (genel tablo)
    table = _fetch_arp_table(
        fgt_ip,
        fgt_device.get("port", 443),
        all_credentials[cred_id],
    )

    with _arp_cache_lock:
        _arp_cache[fgt_ip] = table

    return table


def _ping_and_refresh_arp(
    target_ip: str,
    fgt_device: dict,
    all_credentials: dict,
) -> dict[str, str]:
    """
    Hedef IP'ye FortiGate üzerinden ping gönderir ve ARP tablosunu yeniler.
    Güncellenmiş tabloyu döndürür.
    """
    fgt_ip  = fgt_device["ip"]
    cred_id = fgt_device.get("credential_id", "")
    if not cred_id or cred_id not in all_credentials:
        return {}

    table = _fetch_arp_table(
        fgt_ip,
        fgt_device.get("port", 443),
        all_credentials[cred_id],
        ping_target=target_ip,
    )

    with _arp_cache_lock:
        _arp_cache[fgt_ip] = table

    return table


def clear_arp_cache() -> None:
    """Tarama oturumu başında önbelleği temizler."""
    with _arp_cache_lock:
        _arp_cache.clear()


def get_mac_address(
    target_ip: str,
    inventory: list[dict],
    credentials: dict,
) -> str:
    """
    Hedef IP için MAC adresini bulur.

    Strateji:
      1. Tüm FortiGate'lerin önbellekli ARP tablosuna bak
      2. Bulunamazsa → her FW üzerinden ping at + ARP tablosunu yenile
      3. Hâlâ bulunamazsa → yerel arp -n
    """
    firewalls = _get_all_fortigates(inventory)

    # 1. Önbellekli ARP tablolarına bak
    for fgt in firewalls:
        table = _get_cached_arp(fgt, credentials)
        mac = table.get(target_ip, "")
        if mac:
            logger.debug("MAC bulundu (cache): %s → %s (FW: %s)", target_ip, mac, fgt["ip"])
            return mac

    # 2. Bulunamadı — FW üzerinden ping at, ARP tablosunu yenile
    for fgt in firewalls:
        table = _ping_and_refresh_arp(target_ip, fgt, credentials)
        mac = table.get(target_ip, "")
        if mac:
            logger.debug("MAC bulundu (ping+ARP): %s → %s (FW: %s)", target_ip, mac, fgt["ip"])
            return mac

    # 3. Yerel ARP tablosu
    try:
        result = subprocess.run(
            ["arp", "-n", target_ip],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            for part in line.split():
                if re.match(r"([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}", part):
                    return part
    except Exception:
        pass

    return "N/A"


# ─────────────────────────────────────────────────────────
# SSH deneme
# ─────────────────────────────────────────────────────────

def _try_ssh(ip: str, username: str, password: str) -> bool:
    """Paramiko ile SSH bağlantısı dener. Başarılıysa True döner."""
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            ip, port=22,
            username=username, password=password,
            timeout=SSH_TIMEOUT,
            look_for_keys=False, allow_agent=False,
            banner_timeout=SSH_TIMEOUT,
        )
        client.close()
        return True
    except paramiko.AuthenticationException:
        return False
    except Exception as exc:
        logger.debug("SSH bağlantı hatası %s@%s: %s", username, ip, exc)
        return False


def _detect_device_type_ssh(ip: str, username: str, password: str) -> tuple[str, str, str]:
    """
    Başarılı SSH bağlantısı sonrası cihaz tipi ve hostname tespiti.

    Returns:
        (device_type, version_output, hostname)
    """
    hostname = ""

    def _extract_hostname(output: str, dtype: str) -> str:
        """Komut çıktısından hostname çıkarır."""
        # Cisco: NX-OS "Device name: HOSTNAME" (Nexus serisi)
        if "cisco" in dtype:
            m = re.search(r"Device name:\s*(\S+)", output, re.IGNORECASE)
            if m:
                return m.group(1).strip()
            # IOS/IOS-XE: "HOSTNAME uptime is ..." — sadece "Kernel" olmayan satırlar
            m = re.search(r"^(?!Kernel\b)(\S+)\s+uptime\s+is", output, re.MULTILINE | re.IGNORECASE)
            if m:
                return m.group(1).strip()
        # Huawei: "<HOSTNAME>" prompt veya "sysname"
        if "huawei" in dtype:
            m = re.search(r"<([^>]+)>", output)
            if m:
                return m.group(1).strip()
            m = re.search(r"sysname\s+(\S+)", output, re.IGNORECASE)
            if m:
                return m.group(1).strip()
        # FortiGate / Fortinet SSH
        if "forti" in dtype:
            m = re.search(r"Hostname\s*:\s*(\S+)", output, re.IGNORECASE)
            if m:
                return m.group(1).strip()
            m = re.search(r"hostname\s*=\s*(\S+)", output, re.IGNORECASE)
            if m:
                return m.group(1).strip()
        # H3C Comware: "<HOSTNAME>" prompt veya "H3C MODELNAME uptime is"
        if "comware" in dtype or "h3c" in dtype or "hp_comware" in dtype:
            m = re.search(r"<([^>]+)>", output)
            if m:
                return m.group(1).strip()
            m = re.search(r"^(?:HP|H3C)\s+[\w\-]+\s+uptime", output, re.MULTILINE | re.IGNORECASE)
            # hostname prompt yoksa model/cihaz adina bakma; bos don
        # Extreme Networks ExtremeXOS: "SysName: HOSTNAME" (show switch ciktisi)
        if "extreme" in dtype:
            m = re.search(r"SysName:\s*(\S+)", output, re.IGNORECASE)
            if m:
                return m.group(1).strip()
        # Ruijie: prompt "HOSTNAME#"
        if "ruijie" in dtype:
            m = re.search(r"^(\S+)#", output, re.MULTILINE)
            if m:
                return m.group(1).strip()
        return ""

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            ip, port=22, username=username, password=password,
            timeout=SSH_TIMEOUT, look_for_keys=False, allow_agent=False,
            banner_timeout=SSH_TIMEOUT,
        )

        for cmd, dtype in _DETECT_CMDS:
            try:
                _, stdout, _ = client.exec_command(cmd, timeout=10)
                out = stdout.read().decode(errors="replace")
                if len(out.strip()) > 20:
                    client.close()
                    dtype = _classify_device_type(out, dtype)
                    hostname = _extract_hostname(out, dtype)
                    return dtype, out, hostname
            except Exception:
                continue

        # Interactive shell ile dene — FortiGate, Extreme, Ruijie vb.
        try:
            shell = client.invoke_shell(width=512, height=9999)
            shell.settimeout(10)
            time.sleep(2)
            banner = shell.recv(65535).decode(errors="replace")

            # Extreme ExtremeXOS: banner'da "ExtremeXOS" gecer
            if "extremexos" in banner.lower() or "extreme networks" in banner.lower():
                shell.send("show switch\n")
                time.sleep(2)
                out = shell.recv(65535).decode(errors="replace") if shell.recv_ready() else ""
                client.close()
                hostname = _extract_hostname(banner + out, "extreme_exos")
                return "extreme_exos", banner + out, hostname

            # Ruijie RGOS: banner'da "Ruijie" veya prompt'ta "#" gecer
            if "ruijie" in banner.lower() or "rgos" in banner.lower():
                shell.send("show version\n")
                time.sleep(2)
                out = shell.recv(65535).decode(errors="replace") if shell.recv_ready() else ""
                client.close()
                hostname = _extract_hostname(banner + out, "ruijie_os")
                return "ruijie_os", banner + out, hostname

            # FortiGate / FortiAnalyzer
            shell.send("get system status\n")
            time.sleep(2)
            out = shell.recv(65535).decode(errors="replace") if shell.recv_ready() else ""
            client.close()
            if "Platform" in out or "Version" in out or "Serial" in out:
                hostname = _extract_hostname(out, "fortigate")
                return "fortigate", out, hostname
        except Exception:
            pass

        client.close()
    except Exception as exc:
        logger.debug("Cihaz tipi tespiti başarısız %s: %s", ip, exc)

    return "unknown", "", ""


def try_ssh_credentials(
    ip: str,
    credentials: dict,
) -> dict | None:
    """
    Vault'taki tüm credential çiftlerini deneyerek SSH erişimi arar.

    Returns:
        Başarılı olursa {"credential_id": ..., "username": ...,
                         "password": ..., "device_type": ..., "version_out": ...}
        Başarısız olursa None
    """
    for cred_id, cred in credentials.items():
        username = cred.get("username", "")
        password = cred.get("password", "")
        if not username or not password:
            continue

        logger.debug("SSH deneniyor: %s@%s (cred: %s)", username, ip, cred_id)
        if _try_ssh(ip, username, password):
            device_type, version_out, hostname = _detect_device_type_ssh(ip, username, password)
            return {
                "credential_id": cred_id,
                "username":      username,
                "password":      password,
                "device_type":   device_type,
                "version_out":   version_out,
                "hostname":      hostname,
            }

    return None


# ─────────────────────────────────────────────────────────
# Inventory kayıt
# ─────────────────────────────────────────────────────────

def _get_serial_via_ssh(ip: str, username: str, password: str,
                        device_type: str) -> str:
    """SSH ile cihazın serial numarasını okur."""
    cmd_map = {
        "cisco":   "show version",
        "huawei":  "display version",
        "forti":   "get hardware info",
        "aironet": "show version",
        "aruba":   "show version",
    }
    serial_patterns = [
        r"Serial Number\s*:\s*([A-Za-z0-9]+)",
        r"Processor board ID\s+([A-Za-z0-9]+)",
        r"[Ss]erial[_\s][Nn]o[.:]?\s*([A-Za-z0-9]+)",
        r"SN\s*:\s*([A-Za-z0-9]+)",
        r"SN:\s*([A-Za-z0-9]+)",
        r"[Ss]ystem\s+[Ss]erial\s+[Nn]umber\s*:\s*([A-Za-z0-9]+)",
    ]
    try:
        cmd = next((v for k, v in cmd_map.items() if k in device_type.lower()),
                   "show version")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, port=22, username=username, password=password,
                       timeout=SSH_TIMEOUT, look_for_keys=False, allow_agent=False,
                       banner_timeout=SSH_TIMEOUT)
        _, stdout, _ = client.exec_command(cmd, timeout=10)
        out = stdout.read().decode(errors="replace")
        client.close()
        for pat in serial_patterns:
            m = re.search(pat, out)
            if m:
                sn = m.group(1).strip().upper()
                if len(sn) >= 5:
                    return sn
    except Exception:
        pass
    return ""


def _build_device_name(ip: str, device_type: str) -> str:
    """IP ve cihaz tipinden otomatik cihaz adı üretir."""
    parts = ip.split(".")
    suffix = f"{parts[2]}_{parts[3]}"
    prefix_map = {
        "cisco":      "CISCO",
        "huawei":     "HUAWEI",
        "fortigate":  "FGT",
        "h3c":        "H3C",
        "extreme":    "EXT",
        "ruijie":     "RJ",
        "unknown":    "DEVICE",
    }
    prefix = next((v for k, v in prefix_map.items() if k in device_type.lower()), "DEVICE")
    return f"{prefix}_{suffix}"


def add_to_inventory(
    ip: str,
    device_type: str,
    credential_id: str,
    hostname: str = "",
    name: str = "",
    mac_address: str = "",
    serial_no: str = "",
) -> dict:
    """Yeni cihazı inventory.json'a ekler veya mevcut kaydı günceller.

    Deduplication öncelik sırası:
      1. MAC adresi eşleşmesi → aynı cihaz, IP güncelle / additional_ips'e ekle
      2. Serial numarası eşleşmesi → aynı cihaz, IP güncelle
      3. IP eşleşmesi → zaten kayıtlı

    Thread-safe: paralel taramada race condition önlenir.
    """
    mac_norm  = _normalize_mac(mac_address)
    serial_up = serial_no.strip().upper()

    with _inventory_write_lock:
        inventory = _load_inventory()

        # ── Deduplication ──────────────────────────────────
        # 1. MAC ile eşleştir (AP ve değişken IP'li cihazlar için kritik)
        if mac_norm:
            mac_map = _inventory_by_mac(inventory)
            if mac_norm in mac_map:
                existing = mac_map[mac_norm]
                old_ip   = existing.get("ip", "")
                if old_ip != ip:
                    # IP değişmiş — primary IP'yi güncelle, eski IP'yi additional_ips'e ekle
                    additional = existing.setdefault("additional_ips", [])
                    if old_ip and old_ip not in additional:
                        additional.append(old_ip)
                    if ip in additional:
                        additional.remove(ip)
                    existing["ip"] = ip
                    existing["ip_updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    if hostname and hostname.upper() != existing.get("name", ""):
                        existing["last_seen_hostname"] = hostname.upper()
                    _save_inventory(inventory)
                    logger.info("MAC eşleşti (%s) — IP güncellendi: %s → %s",
                                mac_norm, old_ip, ip)
                    return {"_updated": True, **existing}
                else:
                    logger.info("MAC ve IP aynı, atlanıyor: %s (%s)", mac_norm, ip)
                    return {}

        # 2. Serial ile eşleştir
        if serial_up and serial_up not in ("N/A", "UNKNOWN"):
            serial_map = _inventory_by_serial(inventory)
            if serial_up in serial_map:
                existing = serial_map[serial_up]
                old_ip   = existing.get("ip", "")
                if old_ip != ip:
                    additional = existing.setdefault("additional_ips", [])
                    if old_ip and old_ip not in additional:
                        additional.append(old_ip)
                    if ip in additional:
                        additional.remove(ip)
                    existing["ip"] = ip
                    existing["ip_updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    _save_inventory(inventory)
                    logger.info("Serial eşleşti (%s) — IP güncellendi: %s → %s",
                                serial_up, old_ip, ip)
                    return {"_updated": True, **existing}
                else:
                    logger.info("Serial ve IP aynı, atlanıyor: %s (%s)", serial_up, ip)
                    return {}

        # 3. IP kontrolü
        existing_ips = _inventory_ips(inventory)
        if ip in existing_ips:
            # IP aynı ama MAC/serial bilinmiyor → mevcut kaydı MAC/serial ile güncelle
            for dev in inventory:
                dev_ips = {dev.get("ip")} | set(dev.get("additional_ips", []))
                if ip in dev_ips:
                    changed = False
                    if mac_norm and not dev.get("mac_address"):
                        dev["mac_address"] = mac_norm
                        changed = True
                    if serial_up and serial_up not in ("N/A","") and not dev.get("serial_no"):
                        dev["serial_no"] = serial_up
                        changed = True
                    if changed:
                        _save_inventory(inventory)
                    logger.info("IP zaten kayıtlı, atlanıyor: %s", ip)
                    return {}
            return {}

        # Ad öncelik sırası: hostname > name parametresi > otomatik üretim
        if hostname:
            device_name = hostname.upper()
        elif name:
            device_name = name
        else:
            device_name = _build_device_name(ip, device_type)

        # Temel etiketler
        parts = ip.split(".")
        subnet_tag = f"subnet_{parts[0]}_{parts[1]}_{parts[2]}"
        tags = ["all", "discovered", subnet_tag]
        dt_low = device_type.lower()
        if "cisco" in dt_low:
            tags.append("cisco")
        elif "huawei" in dt_low:
            tags.append("huawei")
        elif "forti" in dt_low:
            tags.append("fortinet")
        elif "h3c" in dt_low or "comware" in dt_low:
            tags.append("h3c")
        elif "extreme" in dt_low:
            tags.append("extreme")
        elif "ruijie" in dt_low or "rgos" in dt_low:
            tags.append("ruijie")
        elif "dell" in dt_low:
            tags.append("dell")
        elif "f5" in dt_low or "bigip" in dt_low:
            tags.append("f5")

        new_device = {
            "name":          device_name,
            "ip":            ip,
            "device_type":   device_type,
            "credential_id": credential_id,
            "tags":          tags,
            "discovered_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        if mac_norm:
            new_device["mac_address"] = mac_norm
        if serial_up and serial_up not in ("N/A", ""):
            new_device["serial_no"] = serial_up

        inventory.append(new_device)
        _save_inventory(inventory)
        logger.info("Yeni cihaz inventory'e eklendi: %s (%s)", device_name, ip)
        return new_device


# ─────────────────────────────────────────────────────────
# Ana tarama motoru
# ─────────────────────────────────────────────────────────

class ScanResult:
    """Tek bir IP tarama sonucu."""

    def __init__(self, ip: str):
        self.ip           = ip
        self.alive        = False
        self.in_inventory = False
        self.mac          = "N/A"
        self.vendor       = "Bilinmiyor"
        self.open_ports:  list[int] = []
        self.ssh_success  = False
        self.ssh_cred_id  = ""
        self.device_type  = ""
        self.serial_no    = ""
        self.added_to_inv = False
        self.ip_updated   = False   # True = mevcut cihazın IP'si güncellendi
        self.inv_name     = ""
        self.error        = ""

    def summary_line(self) -> str:
        status = "✅ INV'e EKLENDİ" if self.added_to_inv else (
                 "🔑 SSH OK"        if self.ssh_success  else (
                 "📭 SSH YOK"       if self.open_ports   else ""))
        ports_str = ",".join(map(str, self.open_ports)) or "-"
        return (f"  {self.ip:<18} MAC:{self.mac:<20} "
                f"Vendor:{self.vendor:<24} Ports:[{ports_str}]  {status}")


def scan_single(
    ip: str,
    inventory: list[dict],
    credentials: dict,
    known_ips: set[str],
) -> ScanResult:
    """Tek bir IP'yi tarar ve ScanResult döndürür."""
    result = ScanResult(ip)

    # 1. Canlılık kontrolü
    result.alive = is_alive(ip)
    if not result.alive:
        return result

    # 2. Inventory kontrolü
    if ip in known_ips:
        result.in_inventory = True
        return result

    print(f"  [YENİ] {ip} — taranıyor...")

    # 3. Port tarama
    result.open_ports = scan_ports(ip)

    # 4. MAC / vendor
    result.mac    = get_mac_address(ip, inventory, credentials)
    result.vendor = mac_vendor.lookup(result.mac)

    # 5. SSH deneme
    if 22 in result.open_ports:
        ssh_info = try_ssh_credentials(ip, credentials)
        if ssh_info:
            result.ssh_success = True
            result.ssh_cred_id = ssh_info["credential_id"]
            result.device_type = ssh_info["device_type"]

            # 6. Inventory'e ekle (hostname varsa name olarak kullan)
            # Serial No çek (AP/switch için değişmez kimlik)
            serial = _get_serial_via_ssh(
                ip, ssh_info["username"], ssh_info["password"],
                result.device_type
            )
            added = add_to_inventory(
                ip,
                result.device_type,
                result.ssh_cred_id,
                hostname=ssh_info.get("hostname", ""),
                mac_address=result.mac,
                serial_no=serial,
            )
            if added:
                if added.get("_updated"):
                    result.ip_updated = True
                    result.inv_name   = added.get("name", "")
                else:
                    result.added_to_inv = True
                    result.inv_name     = added.get("name", "")
            result.serial_no = serial

    return result


def scan_range(
    targets: list[str],
    inventory: list[dict],
    credentials: dict,
    progress_cb=None,
) -> list[ScanResult]:
    """
    Hedef IP listesini paralel tarar.

    Args:
        targets     : Taranacak IP adresleri listesi
        inventory   : Mevcut inventory kaydı
        credentials : Vault'tan gelen tüm credential'lar
        progress_cb : Her IP tamamlandığında çağrılan callback (opsiyonel)

    Returns:
        ScanResult listesi (sadece ayakta olanlar)
    """
    # Her tarama başında ARP önbelleğini temizle
    clear_arp_cache()

    known_ips    = _inventory_ips(inventory)
    excluded     = excluded_ips()
    skip_ips     = known_ips | excluded

    # Exclude'daki IP'leri hedef listesinden çıkar
    filtered_targets = [ip for ip in targets if ip not in excluded]
    skipped_count    = len(targets) - len(filtered_targets)
    if skipped_count:
        logger.debug("Exclude listesinden %d IP atlandı", skipped_count)

    results: list[ScanResult] = []

    with ThreadPoolExecutor(max_workers=HOST_WORKERS) as pool:
        future_map = {
            pool.submit(scan_single, ip, inventory, credentials, skip_ips): ip
            for ip in filtered_targets
        }
        for future in as_completed(future_map):
            ip = future_map[future]
            try:
                res = future.result()
                if res.alive:
                    results.append(res)
                if progress_cb:
                    progress_cb(ip, res)
            except Exception as exc:
                logger.exception("Tarama hatası %s: %s", ip, exc)

    return sorted(results, key=lambda r: ipaddress.ip_address(r.ip))
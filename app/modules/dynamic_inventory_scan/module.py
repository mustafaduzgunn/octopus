"""
app/modules/inventory_collector/module.py
──────────────────────────────────────────
Çalışma modları:
  - main.py üzerinden : selected.run(vault)
  - Doğrudan          : python -m app.modules.inventory_collector.module

Desteklenen cihaz tipleri:
  SSH (Netmiko) : cisco_ios, cisco_nxos, huawei_*, dell_force10, hp_comware
  SSH (Paramiko) : fortianalyzer, fortimanager, fortiauthenticator,
                   fortisandbox, forticlientems, fortiems
  REST : fortigate / fortinet  (FortiOS REST API)
         bigip / f5 / big-ip   (iControl REST)
"""

from __future__ import annotations

import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

import requests
import urllib3
import paramiko
from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

from app.core.base_module import BaseModule
from app.common.vault_helper import resolve_vault

from .parsers import get_parser


def _classify_output(output: str, current_type: str) -> str:
    """
    SSH cikti iceriğini analiz ederek gercek parser tipini dondurur.
    device_type yanlis kaydedilmis olsa bile dogru parseri secmeyi saglar.
    """
    lo = output.lower()
    if "h3c comware" in lo or ("comware" in lo and "h3c" in lo):
        return "h3c_comware"
    if "extremexos" in lo or "extreme networks" in lo:
        return "extreme_exos"
    if "ruijie" in lo or "rgos" in lo:
        return "ruijie_os"
    if ("nx-os" in lo or "nxos" in lo) and "cisco" in lo:
        return "cisco_nxos"
    if "junos" in lo:
        return "juniper"
    if "comware" in lo:
        return "hp_comware"
    # Huawei display version ciktisi
    if "vrp" in lo or "huawei versatile routing" in lo:
        return "huawei"
    # Mevcut tipi koru
    return current_type

if TYPE_CHECKING:
    from app.modules.password_manager.service import VaultService

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

_BASE          = Path(__file__).parent.parent.parent
DATA_DIR       = _BASE / "data"
OUTPUT_DIR     = Path(__file__).parent / "outputs"
INVENTORY_PATH = DATA_DIR / "inventory.json"
MAX_WORKERS    = 5

# ── Tip grupları ──────────────────────────────────────────

_SSH_TYPES = {
    "cisco", "huawei", "dell_force10", "dell",
    "hp_comware", "h3c_comware", "h3c", "hp_procurve", "comware",
    "extreme_exos", "extreme",
    "ruijie_os", "ruijie",
}

# inventory'deki device_type → Netmiko platform adi eslemesi
# Farkli surumlerden gelen veya elle girilmis degerleri normalize eder
_NETMIKO_TYPE_MAP = {
    "extreme_exos":  "extreme_exos",
    "extreme_xos":   "extreme_exos",
    "extreme_os":    "extreme_exos",
    "extreme":       "extreme_exos",
    "ruijie_os":     "ruijie_os",
    "ruijie":        "ruijie_os",
    "rgos":          "ruijie_os",
    "h3c_comware":   "h3c_comware",
    "hp_comware":    "hp_comware",
    "cisco_nxos":    "cisco_nxos",
    "cisco_ios":     "cisco_ios",
    "cisco_xe":      "cisco_xe",
    "cisco_xr":      "cisco_xr",
}

def _netmiko_type(device_type: str) -> str:
    """device_type degerini Netmiko'nun kabul ettigi platform ismine donusturur."""
    dt = device_type.lower().strip()
    return _NETMIKO_TYPE_MAP.get(dt, dt)

_FORTIGATE_TYPES     = {"fortigate", "fortinet"}
_FORTINET_SSH_TYPES  = {"fortianalyzer", "fortimanager", "fortiauthenticator",
                        "fortisandbox", "forticlientems", "fortiems"}
_F5_TYPES            = {"bigip", "f5", "big-ip", "f5_bigip"}


def _is_fortigate(dt: str) -> bool:
    return any(t in dt for t in _FORTIGATE_TYPES) and not _is_fortinet_ssh(dt)

def _is_fortinet_ssh(dt: str) -> bool:
    return any(t in dt for t in _FORTINET_SSH_TYPES)

def _is_f5(dt: str) -> bool:
    return any(t in dt for t in _F5_TYPES)

def _is_ssh(dt: str) -> bool:
    return any(t in dt for t in _SSH_TYPES)


# ── JSON yükleme ──────────────────────────────────────────

def _load_inventory() -> list[dict]:
    with open(INVENTORY_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def _save_inventory(inventory: list[dict]) -> None:
    with open(INVENTORY_PATH, "w", encoding="utf-8") as fh:
        json.dump(inventory, fh, indent=2, ensure_ascii=False)


def _filter_by_tag(inventory: list[dict], tag: str) -> list[dict]:
    if tag.lower() == "all":
        return inventory
    return [d for d in inventory if tag in d.get("tags", [])]


# ── SSH ile envanter toplama ──────────────────────────────

def _collect_generic_fallback(device: dict, credentials: dict, max_retry: int = 3) -> dict:
    """
    device_type 'unknown' veya tanınmayan cihazlar için generic SSH deneme.
    show version / display version / show switch çıktısından cihaz tipini tespit
    ederek doğru parser'a yönlendirir. Başarılı olursa inventory'deki device_type'ı da günceller.
    """
    import re as _re
    from .parsers import get_parser

    name = device["name"]
    ip   = device["ip"]

    _PROBE_CMDS = [
        ("show version",    "cisco_ios"),
        ("display version", "huawei"),
        ("show switch",     "extreme_exos"),
    ]

    def classify(out, initial):
        lo = out.lower()
        if "h3c comware" in lo or ("comware" in lo and _re.search(r"h3c\s+[a-z]\d", out, _re.IGNORECASE)):
            return "h3c_comware"
        if "extremexos" in lo or "extreme networks" in lo:
            return "extreme_exos"
        if "ruijie" in lo or "rgos" in lo:
            return "ruijie_os"
        if "nx-os" in lo or "nxos" in lo:
            return "cisco_nxos"
        if "junos" in lo:
            return "juniper"
        return initial

    for attempt in range(1, max_retry + 1):
        try:
            # generic_ssh ile bağlan — tüm cihazlarla uyumlu
            conn = ConnectHandler(
                device_type="generic",
                host=ip,
                username=credentials.get("username", ""),
                password=credentials.get("password", ""),
                timeout=20,
            )
            detected_type = "unknown"
            version_out   = ""
            extra_out     = ""

            for cmd, initial_type in _PROBE_CMDS:
                try:
                    out = conn.send_command(cmd, read_timeout=30, expect_string=r"[>#\$]")
                    if out and len(out.strip()) > 20:
                        detected_type = classify(out, initial_type)
                        version_out   = out
                        break
                except Exception:
                    continue

            # Extreme: show switch aldık, şimdi show version de al
            if "extreme" in detected_type and version_out:
                try:
                    extra_out = conn.send_command("show version", read_timeout=30)
                except Exception:
                    pass

            conn.disconnect()

            if detected_type == "unknown" or not version_out:
                raise ValueError("Cihaz tipi tespit edilemedi — tüm probe komutları başarısız")

            # inventory'deki device_type'ı güncelle
            try:
                inv = _load_inventory()
                for d in inv:
                    if d.get("ip") == ip:
                        d["device_type"] = detected_type
                        break
                _save_inventory(inv)
                logger.info("%s — device_type güncellendi: unknown → %s", name, detected_type)
            except Exception as e:
                logger.warning("%s — device_type güncellenemedi: %s", name, e)

            parser = get_parser(detected_type)
            if not parser:
                raise ValueError(f"Parser bulunamadı: {detected_type}")

            parsed = parser(version_out, extra_out)
            logger.info("%s — generic fallback ile envanter alındı (%s)", name, detected_type)
            result_data = {"device": name, "ip": ip, **parsed}
            if parsed.get("hostname"):
                result_data["collected_hostname"] = parsed["hostname"]
            return {"success": True, "data": result_data}

        except Exception as exc:
            last_err = str(exc)
            logger.warning("%s — generic fallback deneme %d başarısız: %s", name, attempt, exc)
            if attempt < max_retry:
                import time as _time
                _time.sleep(2)

    return {"success": False, "device": name, "ip": ip,
            "error": f"Generic fallback başarısız: {last_err}"}


def _collect_ssh(device: dict, credentials: dict, max_retry: int = 3) -> dict:
    name    = device["name"]
    dt      = device["device_type"].lower()
    last_err = ""

    # Cihaz tipine gore komutlar
    # NOT: device_type Netmiko platform ismine uygun olmalidir
    if "cisco" in dt:
        cmd_version = "show version"
        cmd_extra   = "show inventory"
    elif "huawei" in dt:
        cmd_version = "display version"
        cmd_extra   = "display device elabel brief"
    elif "dell_force10" in dt or "dell" in dt:
        cmd_version = "show version"
        cmd_extra   = "show inventory"
    elif "h3c_comware" in dt or "hp_comware" in dt or "comware" in dt or "h3c" in dt:
        cmd_version = "display version"
        cmd_extra   = "display device manuinfo"
    elif "extreme_exos" in dt or "extreme" in dt:
        cmd_version = "show switch"
        cmd_extra   = "show version"
    elif "ruijie_os" in dt or "ruijie" in dt:
        cmd_version = "show version"
        cmd_extra   = ""
    elif _is_fortinet_ssh(dt):
        return _collect_fortinet_ssh(device, credentials, max_retry)
    elif dt in ("unknown", "") or dt not in _SSH_TYPES and not _is_fortinet_ssh(dt) and not _is_fortigate(dt) and not _is_f5(dt):
        # Bilinmeyen veya henuz tespit edilememis tipler icin
        # show version ile generic deneme yap, ciktiyi analiz ederek dogru yola yonlendir
        logger.warning("%s — bilinmeyen tip '%s', generic show version deneniyor", name, dt)
        return _collect_generic_fallback(device, credentials, max_retry)
    else:
        msg = f"Desteklenmeyen SSH cihaz tipi: {device['device_type']}"
        logger.error("%s — %s", name, msg)
        return {"success": False, "device": name, "ip": device["ip"], "error": msg}

    netmiko_dt = _netmiko_type(device["device_type"])
    for attempt in range(1, max_retry + 1):
        try:
            logger.debug("%s — SSH deneme %d/%d (netmiko_type=%s)", name, attempt, max_retry, netmiko_dt)
            conn = ConnectHandler(
                device_type=netmiko_dt,
                host=device["ip"],
                username=credentials.get("username", ""),
                password=credentials.get("password", ""),
                timeout=20,
            )
            version_out = conn.send_command(cmd_version, read_timeout=60)
            extra_out   = conn.send_command(cmd_extra, read_timeout=60) if cmd_extra else ""
            conn.disconnect()

            if not version_out:
                raise ValueError("Boş çıktı alındı")

            # Cikti iceriginden gercek cihaz tipini tespit et
            # (device_type yanlis kaydedilmis olabilir — ornegin cisco_ios iken ruijie gelirse)
            real_type = _classify_output(version_out, device["device_type"])
            if real_type != device["device_type"]:
                logger.info("%s — cikti analizine gore tip duzeltildi: %s → %s",
                            name, device["device_type"], real_type)

            # Cisco AP ozel tespiti
            from .parsers import _is_cisco_ap, parse_cisco_ap
            if "cisco" in real_type.lower() and _is_cisco_ap(version_out):
                parser = parse_cisco_ap
                logger.debug("%s — Cisco AP tespit edildi, AP parser kullanılıyor", name)
            else:
                parser = get_parser(real_type)
            if not parser:
                raise ValueError(f"Parser bulunamadı: {real_type} (orijinal: {device['device_type']})")

            parsed = parser(version_out, extra_out)
            logger.info("%s — SSH envanter alındı", name)
            result_data = {"device": name, "ip": device["ip"], **parsed}
            # hostname parser'dan geldiyse, device_name olarak da sakla
            if parsed.get("hostname"):
                result_data["collected_hostname"] = parsed["hostname"]
            return {"success": True, "data": result_data}

        except (NetmikoAuthenticationException, NetmikoTimeoutException) as exc:
            last_err = str(exc)
            logger.error("%s — SSH kritik hata: %s", name, exc)
            break   # auth/timeout → retry yok
        except Exception as exc:
            last_err = str(exc)
            logger.warning("%s — SSH deneme %d başarısız: %s", name, attempt, exc)
            if attempt < max_retry:
                time.sleep(3)

    return {"success": False, "device": name, "ip": device["ip"],
            "error": last_err or f"{max_retry} deneme başarısız"}


# ── FortiGate REST ile envanter toplama ───────────────────

def _collect_fortigate(device: dict, credentials: dict, max_retry: int = 3) -> dict:
    name      = device["name"]
    ip        = device["ip"]
    port      = device.get("port", 443)
    api_token = credentials.get("api_token", "")
    username  = credentials.get("username", "")
    password  = credentials.get("password", "")
    base_url  = f"https://{ip}:{port}"
    last_err  = ""

    for attempt in range(1, max_retry + 1):
        try:
            logger.debug("%s — FortiGate REST deneme %d/%d", name, attempt, max_retry)
            session = requests.Session()
            session.verify = False

            if api_token:
                session.headers["Authorization"] = f"Bearer {api_token}"
                params = {"scope": "global", "access_token": api_token}
            else:
                r = session.post(
                    f"{base_url}/logincheck",
                    data={"username": username, "secretkey": password},
                    timeout=15,
                )
                r.raise_for_status()
                csrf = r.cookies.get("ccsrftoken", "").strip('"')
                if csrf:
                    session.headers["X-CSRFTOKEN"] = csrf
                params = {"scope": "global"}

            # Sistem durumu
            status_resp = session.get(
                f"{base_url}/api/v2/monitor/system/status",
                params=params, timeout=20,
            )
            status_resp.raise_for_status()
            status_data = status_resp.json()

            # Global config (hostname yedek)
            global_data = None
            try:
                g_resp = session.get(
                    f"{base_url}/api/v2/cmdb/system/global",
                    params=params, timeout=15,
                )
                if g_resp.ok:
                    global_data = g_resp.json()
            except Exception:
                pass

            # HA üye seri numaraları
            ha_members = []
            try:
                ha_resp = session.get(
                    f"{base_url}/api/v2/monitor/system/ha-peer",
                    params=params, timeout=15,
                )
                if ha_resp.ok:
                    peers = ha_resp.json().get("results", [])
                    if isinstance(peers, list):
                        for peer in peers:
                            sn = peer.get("serial_no") or peer.get("serial") or peer.get("sn")
                            hn = peer.get("hostname") or peer.get("host_name", "")
                            role = peer.get("role", "")
                            if sn:
                                ha_members.append({"serial": sn, "hostname": hn, "role": role})
            except Exception:
                pass

            session.close()

            parser = get_parser(device["device_type"])
            parsed = parser(status_data, global_data)
            if ha_members:
                parsed["ha_members"] = ha_members
            logger.info("%s — FortiGate REST envanter alındı", name)
            return {"success": True, "data": {"device": name, "ip": ip, **parsed}}

        except Exception as exc:
            last_err = str(exc)
            logger.warning("%s — FortiGate REST deneme %d başarısız: %s", name, attempt, exc)
            if attempt < max_retry:
                time.sleep(3)

    return {"success": False, "device": name, "ip": ip,
            "error": last_err or f"{max_retry} deneme başarısız"}


# ── F5 BIG-IP iControl REST ile envanter toplama ──────────

def _get_f5_token(session: requests.Session, base_url: str,
                  username: str, password: str) -> str:
    """F5 auth token alır; başarısızsa boş string döner.

    BIG-IP 17.x hem Basic auth header'ı hem de JSON body'i birlikte bekler.
    """
    import base64 as _b64, json as _json
    b64 = _b64.b64encode(f"{username}:{password}".encode()).decode()

    for provider in ["tmos", "local"]:
        try:
            body_bytes = _json.dumps(
                {"username": username, "password": password, "loginProviderName": provider}
            ).encode("utf-8")
            resp = session.post(
                f"{base_url}/mgmt/shared/authn/login",
                data=body_bytes,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Basic {b64}",
                },
                timeout=15,
            )
            token = resp.json().get("token", {}).get("token", "")
            if token:
                return token
        except Exception:
            pass
    return ""


def _collect_f5(device: dict, credentials: dict, max_retry: int = 3) -> dict:
    name     = device["name"]
    ip       = device["ip"]
    port     = device.get("port", 443)
    username = credentials.get("username", "")
    password = credentials.get("password", "")
    base_url = f"https://{ip}:{port}"
    last_err = ""

    for attempt in range(1, max_retry + 1):
        try:
            logger.debug("%s — F5 REST deneme %d/%d", name, attempt, max_retry)
            session = requests.Session()
            session.verify = False
            session.headers["Content-Type"] = "application/json"

            token = _get_f5_token(session, base_url, username, password)
            if token:
                session.headers["X-F5-Auth-Token"] = token
            else:
                # Token alınamadı — Basic auth son çare (eski BIG-IP sürümleri)
                import base64 as _b64
                _b64str = _b64.b64encode(f"{username}:{password}".encode()).decode()
                session.headers["Authorization"] = f"Basic {_b64str}"
                logger.debug("%s — F5 token alınamadı, Basic auth deneniyor", name)

            # Sürüm
            ver_resp = session.get(f"{base_url}/mgmt/tm/sys/version", timeout=20)
            ver_resp.raise_for_status()

            # Donanım
            hw_data = None
            try:
                hw_resp = session.get(f"{base_url}/mgmt/tm/sys/hardware", timeout=20)
                if hw_resp.ok:
                    hw_data = hw_resp.json()
            except Exception:
                pass

            # Cihaz kimliği
            dev_info = None
            try:
                di_resp = session.get(
                    f"{base_url}/mgmt/shared/identified-devices/config/device-info",
                    timeout=20,
                )
                if di_resp.ok:
                    dev_info = di_resp.json()
            except Exception:
                pass

            session.close()

            parser = get_parser(device["device_type"])
            parsed = parser(ver_resp.json(), hw_data, dev_info)
            logger.info("%s — F5 REST envanter alındı", name)
            return {"success": True, "data": {"device": name, "ip": ip, **parsed}}

        except Exception as exc:
            last_err = str(exc)
            logger.warning("%s — F5 REST deneme %d başarısız: %s", name, attempt, exc)
            if attempt < max_retry:
                time.sleep(3)

    return {"success": False, "device": name, "ip": ip,
            "error": last_err or f"{max_retry} deneme başarısız"}


# ── Fortinet SSH (FAZ/FMG/FAC/FSB/EMS) ile envanter ─────

_SSH_CMD_TIMEOUT = 60   # saniye

def _collect_fortinet_ssh(device: dict, credentials: dict, max_retry: int = 3) -> dict:
    """
    FortiAnalyzer, FortiManager, FortiAuthenticator, FortiSandbox, EMS
    cihazlarından 'get system status' komutuyla envanter toplar.
    Paramiko interactive shell kullanılır (Netmiko bu tipleri desteklemez).
    """
    name     = device["name"]
    ip       = device["ip"]
    port     = device.get("port", 22)
    username = credentials.get("username", "")
    password = credentials.get("password", "")
    last_err = ""

    for attempt in range(1, max_retry + 1):
        try:
            logger.debug("%s — Fortinet SSH deneme %d/%d", name, attempt, max_retry)

            conn = paramiko.SSHClient()
            conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            conn.connect(ip, port=port, username=username, password=password,
                         timeout=30, look_for_keys=False, allow_agent=False)

            shell = conn.invoke_shell(width=512, height=9999)
            shell.settimeout(_SSH_CMD_TIMEOUT)
            time.sleep(2)
            shell.recv(65535)   # banner / prompt temizle

            shell.send("get system status\n")
            time.sleep(2)

            output_parts: list[str] = []
            deadline = time.time() + _SSH_CMD_TIMEOUT
            while time.time() < deadline:
                if shell.recv_ready():
                    chunk = shell.recv(65535).decode(errors="replace")
                    output_parts.append(chunk)
                    time.sleep(0.3)
                else:
                    time.sleep(1)
                    if not shell.recv_ready():
                        break

            conn.close()
            output = "".join(output_parts)

            if len(output.strip()) < 50:
                raise ValueError(f"Çok kısa çıktı alındı ({len(output)} karakter)")

            parser = get_parser(device["device_type"])
            if not parser:
                raise ValueError(f"Parser bulunamadı: {device['device_type']}")

            parsed = parser(output, device["device_type"])
            logger.info("%s — Fortinet SSH envanter alındı", name)
            return {"success": True, "data": {"device": name, "ip": ip, **parsed}}

        except paramiko.AuthenticationException as exc:
            last_err = str(exc)
            logger.error("%s — SSH auth hatası: %s", name, exc)
            break   # auth hatası → retry yok
        except Exception as exc:
            last_err = str(exc)
            logger.warning("%s — Fortinet SSH deneme %d başarısız: %s", name, attempt, exc)
            if attempt < max_retry:
                time.sleep(3)

    return {"success": False, "device": name, "ip": ip,
            "error": last_err or f"{max_retry} deneme başarısız"}


def _paramiko_send_cmd(shell, cmd: str, wait: float = 2.0, timeout: float = 15.0) -> str:
    """Paramiko interactive shell üzerinden komut gönderir ve çıktı okur."""
    import time as _t
    shell.send(cmd + "\n")
    _t.sleep(wait)
    parts = []
    deadline = _t.time() + timeout
    while _t.time() < deadline:
        if shell.recv_ready():
            parts.append(shell.recv(65535).decode(errors="replace"))
            _t.sleep(0.3)
        else:
            _t.sleep(0.5)
            if not shell.recv_ready():
                break
    return "".join(parts)


def _collect_ruijie(device: dict, credentials: dict, max_retry: int = 3) -> dict:
    """
    Ruijie RGOS cihazlarından paramiko interactive shell ile envanter toplar.
    Netmiko ruijie_os driver'i prompt uyumsuzluğu yaşayabileceğinden
    doğrudan paramiko kullanılır.
    """
    name     = device["name"]
    ip       = device["ip"]
    port     = device.get("port", 22)
    username = credentials.get("username", "")
    password = credentials.get("password", "")
    last_err = ""

    for attempt in range(1, max_retry + 1):
        try:
            logger.debug("%s — Ruijie SSH deneme %d/%d", name, attempt, max_retry)
            conn = paramiko.SSHClient()
            conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            conn.connect(ip, port=port, username=username, password=password,
                         timeout=30, look_for_keys=False, allow_agent=False)

            shell = conn.invoke_shell(width=512, height=9999)
            shell.settimeout(_SSH_CMD_TIMEOUT)
            time.sleep(2)
            shell.recv(65535)  # banner temizle

            version_out = _paramiko_send_cmd(shell, "show version", wait=2.0)
            conn.close()

            if len(version_out.strip()) < 30:
                raise ValueError(f"Çok kısa çıktı ({len(version_out)} karakter)")

            real_type = _classify_output(version_out, device["device_type"])
            parser    = get_parser(real_type)
            if not parser:
                raise ValueError(f"Parser bulunamadı: {real_type}")

            parsed = parser(version_out, "")
            logger.info("%s — Ruijie envanter alındı", name)
            result_data = {"device": name, "ip": ip, **parsed}
            if parsed.get("hostname"):
                result_data["collected_hostname"] = parsed["hostname"]
            return {"success": True, "data": result_data}

        except paramiko.AuthenticationException as exc:
            last_err = str(exc)
            logger.error("%s — SSH auth hatası: %s", name, exc)
            break
        except Exception as exc:
            last_err = str(exc)
            logger.warning("%s — Ruijie SSH deneme %d başarısız: %s", name, attempt, exc)
            if attempt < max_retry:
                time.sleep(3)

    return {"success": False, "device": name, "ip": ip,
            "error": last_err or f"{max_retry} deneme başarısız"}


def _collect_extreme(device: dict, credentials: dict, max_retry: int = 3) -> dict:
    """
    Extreme Networks ExtremeXOS cihazlarından paramiko ile envanter toplar.
    show switch (ana bilgi) + show version (serial) çeker.
    """
    name     = device["name"]
    ip       = device["ip"]
    port     = device.get("port", 22)
    username = credentials.get("username", "")
    password = credentials.get("password", "")
    last_err = ""

    for attempt in range(1, max_retry + 1):
        try:
            logger.debug("%s — Extreme SSH deneme %d/%d", name, attempt, max_retry)
            conn = paramiko.SSHClient()
            conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            conn.connect(ip, port=port, username=username, password=password,
                         timeout=30, look_for_keys=False, allow_agent=False)

            shell = conn.invoke_shell(width=512, height=9999)
            shell.settimeout(_SSH_CMD_TIMEOUT)
            time.sleep(2)
            shell.recv(65535)  # banner temizle

            switch_out  = _paramiko_send_cmd(shell, "show switch",  wait=2.0)
            version_out = _paramiko_send_cmd(shell, "show version", wait=2.0)
            conn.close()

            if len(switch_out.strip()) < 20:
                raise ValueError(f"show switch çok kısa çıktı ({len(switch_out)} karakter)")

            from .parsers.extreme import parse_extreme
            parsed = parse_extreme(switch_out, version_out)
            logger.info("%s — Extreme envanter alındı", name)
            result_data = {"device": name, "ip": ip, **parsed}
            if parsed.get("hostname"):
                result_data["collected_hostname"] = parsed["hostname"]
            return {"success": True, "data": result_data}

        except paramiko.AuthenticationException as exc:
            last_err = str(exc)
            logger.error("%s — SSH auth hatası: %s", name, exc)
            break
        except Exception as exc:
            last_err = str(exc)
            logger.warning("%s — Extreme SSH deneme %d başarısız: %s", name, attempt, exc)
            if attempt < max_retry:
                time.sleep(3)

    return {"success": False, "device": name, "ip": ip,
            "error": last_err or f"{max_retry} deneme başarısız"}


# ── Genel dispatch ────────────────────────────────────────

def _collect_single(device: dict, credentials: dict, max_retry: int = 3) -> dict:
    dt = device.get("device_type", "").lower()
    if _is_fortinet_ssh(dt):
        return _collect_fortinet_ssh(device, credentials, max_retry)
    if _is_fortigate(dt):
        return _collect_fortigate(device, credentials, max_retry)
    if _is_f5(dt):
        return _collect_f5(device, credentials, max_retry)
    # Ruijie ve Extreme: Netmiko yerine dogrudan paramiko kullanan ozel fonksiyonlar
    if "ruijie" in dt or "rgos" in dt:
        return _collect_ruijie(device, credentials, max_retry)
    if "extreme" in dt:
        return _collect_extreme(device, credentials, max_retry)
    return _collect_ssh(device, credentials, max_retry)


# ── Kaydetme ──────────────────────────────────────────────

def _save_results(results: list, failed: list) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file  = OUTPUT_DIR / f"inventory_result_{timestamp}.json"
    out_file.write_text(
        json.dumps({"successful": results, "failed": failed}, indent=4, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"\n  Sonuç kaydedildi: {out_file}")
    logger.info("Envanter sonucu kaydedildi: %s", out_file)


# ── Modül sınıfı ─────────────────────────────────────────

class InventoryCollectorModule(BaseModule):
    """Ağ cihazlarından envanter toplayan modül."""

    def info(self) -> dict[str, str]:
        return {
            "name": "Inventory Collector",
            "description": "Ağ cihazlarından donanım/yazılım envanteri toplar.",
        }

    def run(self, vault: "VaultService | None" = None) -> None:
        v = resolve_vault(vault)

        inventory = _load_inventory()
        tag       = input("  Tag girin ('all' için hepsini al): ").strip()
        devices   = _filter_by_tag(inventory, tag)

        if not devices:
            print(f"  '{tag}' tag'ine sahip cihaz bulunamadı.")
            input("  Enter'a basın...")
            return

        print(f"\n  {len(devices)} cihaz işlenecek...\n")
        results: list = []
        failed:  list = []

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            future_map: dict = {}
            for device in devices:
                cred_id = device.get("credential_id", "")
                if not cred_id or cred_id not in v.vault:
                    print(f"  [ATLA] {device['name']} — credential bulunamadı")
                    logger.warning("Credential bulunamadı: %s", cred_id)
                    continue
                future_map[
                    pool.submit(_collect_single, device, v.vault[cred_id])
                ] = device

            for future in as_completed(future_map):
                try:
                    res = future.result()
                except Exception as exc:
                    dev = future_map[future]
                    logger.exception("Future hatası — %s: %s", dev["name"], exc)
                    failed.append({"device": dev["name"], "ip": dev["ip"], "error": str(exc)})
                    continue

                if res["success"]:
                    results.append(res["data"])
                else:
                    failed.append(res)

        _save_results(results, failed)

        print(f"\n  {'─'*44}")
        print(f"  ✅ Başarılı : {len(results)} / {len(devices)}")
        if failed:
            print(f"  ❌ Başarısız: {len(failed)} / {len(devices)}")
        print(f"  {'─'*44}")

        if failed:
            print(f"\n  Envanter alınamayan cihazlar ({len(failed)}):")
            for idx, d in enumerate(sorted(failed, key=lambda x: x.get("device", "")), start=1):
                print(f"    {idx:>3}. {d.get('device')}  ({d.get('ip')})")
                print(f"         Sebep: {d.get('error')}")
        else:
            print("\n  Tüm cihazlardan envanter alındı.")

        input("\n  Enter'a basın...")


if __name__ == "__main__":
    InventoryCollectorModule().run()
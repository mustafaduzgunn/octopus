"""
app/modules/inventory_collector/module.py
──────────────────────────────────────────
Çalışma modları:
  - main.py üzerinden : selected.run(vault)
  - Doğrudan          : python -m app.modules.inventory_collector.module

Desteklenen cihaz tipleri:
  SSH (Netmiko)  : cisco_ios, cisco_nxos, huawei_*, dell_force10,
                   hp_comware, h3c_comware
  SSH (Paramiko) : extreme_exos, ruijie_os,
                   fortianalyzer, fortimanager, fortiauthenticator,
                   fortisandbox, forticlientems, fortiems
  REST           : fortigate / fortinet  (FortiOS REST API)
                   bigip / f5 / big-ip   (iControl REST)
"""

from __future__ import annotations

import json
import logging
import re
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

_FORTIGATE_TYPES     = {"fortigate", "fortinet"}
_FORTINET_SSH_TYPES  = {"fortianalyzer", "fortimanager", "fortiauthenticator",
                        "fortisandbox", "forticlientems", "fortiems"}
_F5_TYPES            = {"bigip", "f5", "big-ip", "f5_bigip"}

# Paramiko komut gönderme için ortak timeout (saniye)
_SSH_CMD_TIMEOUT = 60


def _is_fortigate(dt: str) -> bool:
    return any(t in dt for t in _FORTIGATE_TYPES) and not _is_fortinet_ssh(dt)

def _is_fortinet_ssh(dt: str) -> bool:
    return any(t in dt for t in _FORTINET_SSH_TYPES)

def _is_f5(dt: str) -> bool:
    return any(t in dt for t in _F5_TYPES)

def _is_extreme(dt: str) -> bool:
    return "extreme" in dt

def _is_ruijie(dt: str) -> bool:
    return "ruijie" in dt or "rgos" in dt


# ── JSON yükleme ──────────────────────────────────────────

def _load_inventory() -> list[dict]:
    with open(INVENTORY_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def _filter_by_tag(inventory: list[dict], tag: str) -> list[dict]:
    if tag.lower() == "all":
        return inventory
    return [d for d in inventory if tag in d.get("tags", [])]


# ── Paramiko yardımcısı ───────────────────────────────────

def _paramiko_send_cmd(
    shell: paramiko.Channel,
    cmd: str,
    wait: float = 2.0,
    timeout: float = _SSH_CMD_TIMEOUT,
) -> str:
    """
    Paramiko interactive shell\'e komut gönderir ve çıktısını okur.
    Banner temizleme içermez — önce shell.recv(65535) ile banner temizlenmiş olmalı.
    """
    shell.send(cmd + "\n")
    time.sleep(wait)
    output_parts: list[str] = []
    deadline = time.time() + timeout
    while time.time() < deadline:
        if shell.recv_ready():
            chunk = shell.recv(65535).decode(errors="replace")
            output_parts.append(chunk)
            time.sleep(0.3)
        else:
            time.sleep(0.5)
            if not shell.recv_ready():
                break
    return "".join(output_parts)


# ── Extreme Networks ExtremeXOS — Paramiko ───────────────

def _collect_extreme(device: dict, credentials: dict, max_retry: int = 3) -> dict:
    """
    Extreme Networks ExtremeXOS cihazlarından envanter toplar.
    Netmiko extreme_exos driver yerine doğrudan paramiko interactive shell kullanır.

    Akış:
        paramiko bağlan → invoke_shell → banner oku
        → show switch  gönder → switch_out
        → show version gönder → version_out
        → parse_extreme(switch_out, version_out) → result_data
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
            shell.recv(65535)   # banner / prompt temizle

            switch_out  = _paramiko_send_cmd(shell, "show switch",  wait=2)
            version_out = _paramiko_send_cmd(shell, "show version", wait=2)
            conn.close()

            if not switch_out.strip():
                raise ValueError("show switch\'ten bos cikti alindi")

            parser = get_parser(device["device_type"])
            if not parser:
                raise ValueError(f"Parser bulunamadi: {device['device_type']}")

            parsed = parser(switch_out, version_out)
            logger.info("%s — Extreme envanter alindi", name)
            result_data = {"device": name, "ip": ip, **parsed}
            if parsed.get("hostname"):
                result_data["collected_hostname"] = parsed["hostname"]
            return {"success": True, "data": result_data}

        except paramiko.AuthenticationException as exc:
            last_err = str(exc)
            logger.error("%s — SSH auth hatasi: %s", name, exc)
            break
        except Exception as exc:
            last_err = str(exc)
            logger.warning("%s — Extreme deneme %d basarisiz: %s", name, attempt, exc)
            if attempt < max_retry:
                time.sleep(3)

    return {"success": False, "device": name, "ip": ip,
            "error": last_err or f"{max_retry} deneme basarisiz"}


# ── Ruijie Networks RGOS — Paramiko ──────────────────────

def _collect_ruijie(device: dict, credentials: dict, max_retry: int = 3) -> dict:
    """
    Ruijie Networks RGOS cihazlarindan envanter toplar.
    Netmiko ruijie_os driver yerine dogrudan paramiko interactive shell kullanir.

    Akis:
        paramiko baglan → invoke_shell → banner oku
        → show version gonder → version_out
        → parse_ruijie(version_out) → result_data
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
            shell.recv(65535)   # banner / prompt temizle

            version_out = _paramiko_send_cmd(shell, "show version", wait=2)
            conn.close()

            if not version_out.strip():
                raise ValueError("show version\'dan bos cikti alindi")

            parser = get_parser(device["device_type"])
            if not parser:
                raise ValueError(f"Parser bulunamadi: {device['device_type']}")

            parsed = parser(version_out)
            logger.info("%s — Ruijie envanter alindi", name)
            result_data = {"device": name, "ip": ip, **parsed}
            if parsed.get("hostname"):
                result_data["collected_hostname"] = parsed["hostname"]
            return {"success": True, "data": result_data}

        except paramiko.AuthenticationException as exc:
            last_err = str(exc)
            logger.error("%s — SSH auth hatasi: %s", name, exc)
            break
        except Exception as exc:
            last_err = str(exc)
            logger.warning("%s — Ruijie deneme %d basarisiz: %s", name, attempt, exc)
            if attempt < max_retry:
                time.sleep(3)

    return {"success": False, "device": name, "ip": ip,
            "error": last_err or f"{max_retry} deneme basarisiz"}


# ── SSH ile envanter toplama (Netmiko) ────────────────────

def _collect_ssh(device: dict, credentials: dict, max_retry: int = 3) -> dict:
    """
    Cisco, Huawei, Dell, HP/H3C Comware gibi Netmiko destekli cihazlar icin
    envanter toplar.

    Komut haritasi:
        cisco_*      : show version        + show inventory
        huawei       : display version     + display device elabel brief
        dell_force10 : show version        + show inventory
        h3c_comware  : display version     + display device manuinfo
    """
    name     = device["name"]
    dt       = device["device_type"].lower()
    last_err = ""

    if "cisco" in dt:
        cmd_version = "show version"
        cmd_extra   = "show inventory"
    elif "huawei" in dt:
        cmd_version = "display version"
        cmd_extra   = "display elabel brief"
    elif "dell_force10" in dt or "dell" in dt:
        cmd_version = "show version"
        cmd_extra   = "show inventory"
    elif "hp_comware" in dt or "comware" in dt or "h3c" in dt or "hp_procurve" in dt:
        cmd_version = "display version"
        cmd_extra   = "display device manuinfo"
    elif _is_fortinet_ssh(dt):
        return _collect_fortinet_ssh(device, credentials, max_retry)
    else:
        msg = f"Desteklenmeyen SSH cihaz tipi: {device['device_type']}"
        logger.error("%s — %s", name, msg)
        return {"success": False, "device": name, "ip": device["ip"], "error": msg}

    for attempt in range(1, max_retry + 1):
        try:
            logger.debug("%s — SSH deneme %d/%d", name, attempt, max_retry)
            conn = ConnectHandler(
                device_type=device["device_type"],
                host=device["ip"],
                username=credentials.get("username", ""),
                password=credentials.get("password", ""),
                timeout=20,
            )
            version_out = conn.send_command(cmd_version, read_timeout=60)
            extra_out   = conn.send_command(cmd_extra, read_timeout=60) if cmd_extra else ""
            conn.disconnect()

            if not version_out:
                raise ValueError("Bos cikti alindi")

            from .parsers import _is_cisco_ap, parse_cisco_ap
            if "cisco" in device["device_type"].lower() and _is_cisco_ap(version_out):
                parser = parse_cisco_ap
                logger.debug("%s — Cisco AP tespit edildi, AP parser kullaniliyor", name)
            else:
                parser = get_parser(device["device_type"])
            if not parser:
                raise ValueError(f"Parser bulunamadi: {device['device_type']}")

            parsed = parser(version_out, extra_out)
            logger.info("%s — SSH envanter alindi", name)
            result_data = {"device": name, "ip": device["ip"], **parsed}
            if parsed.get("hostname"):
                result_data["collected_hostname"] = parsed["hostname"]
            return {"success": True, "data": result_data}

        except (NetmikoAuthenticationException, NetmikoTimeoutException) as exc:
            last_err = str(exc)
            logger.error("%s — SSH kritik hata: %s", name, exc)
            break
        except Exception as exc:
            last_err = str(exc)
            logger.warning("%s — SSH deneme %d basarisiz: %s", name, attempt, exc)
            if attempt < max_retry:
                time.sleep(3)

    return {"success": False, "device": name, "ip": device["ip"],
            "error": last_err or f"{max_retry} deneme basarisiz"}


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
                csrf = r.cookies.get("ccsrftoken", "").strip('"\'"')
                if csrf:
                    session.headers["X-CSRFTOKEN"] = csrf
                params = {"scope": "global"}

            status_resp = session.get(
                f"{base_url}/api/v2/monitor/system/status",
                params=params, timeout=20,
            )
            status_resp.raise_for_status()
            status_data = status_resp.json()

            global_data = None
            try:
                g_resp = session.get(f"{base_url}/api/v2/cmdb/system/global",
                                     params=params, timeout=15)
                if g_resp.ok:
                    global_data = g_resp.json()
            except Exception:
                pass

            ha_members = []
            try:
                ha_resp = session.get(f"{base_url}/api/v2/monitor/system/ha-peer",
                                      params=params, timeout=15)
                if ha_resp.ok:
                    peers = ha_resp.json().get("results", [])
                    if isinstance(peers, list):
                        for peer in peers:
                            sn   = peer.get("serial_no") or peer.get("serial") or peer.get("sn")
                            hn   = peer.get("hostname") or peer.get("host_name", "")
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
            logger.info("%s — FortiGate REST envanter alindi", name)
            return {"success": True, "data": {"device": name, "ip": ip, **parsed}}

        except Exception as exc:
            last_err = str(exc)
            logger.warning("%s — FortiGate REST deneme %d basarisiz: %s", name, attempt, exc)
            if attempt < max_retry:
                time.sleep(3)

    return {"success": False, "device": name, "ip": ip,
            "error": last_err or f"{max_retry} deneme basarisiz"}


# ── F5 BIG-IP iControl REST ile envanter toplama ──────────

def _get_f5_token(session: requests.Session, base_url: str,
                  username: str, password: str) -> str:
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
                headers={"Content-Type": "application/json", "Authorization": f"Basic {b64}"},
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
                import base64 as _b64
                _b64str = _b64.b64encode(f"{username}:{password}".encode()).decode()
                session.headers["Authorization"] = f"Basic {_b64str}"
                logger.debug("%s — F5 token alinamadi, Basic auth deneniyor", name)

            ver_resp = session.get(f"{base_url}/mgmt/tm/sys/version", timeout=20)
            ver_resp.raise_for_status()

            hw_data = None
            try:
                hw_resp = session.get(f"{base_url}/mgmt/tm/sys/hardware", timeout=20)
                if hw_resp.ok:
                    hw_data = hw_resp.json()
            except Exception:
                pass

            dev_info = None
            try:
                di_resp = session.get(
                    f"{base_url}/mgmt/shared/identified-devices/config/device-info", timeout=20)
                if di_resp.ok:
                    dev_info = di_resp.json()
            except Exception:
                pass

            session.close()
            parser = get_parser(device["device_type"])
            parsed = parser(ver_resp.json(), hw_data, dev_info)
            logger.info("%s — F5 REST envanter alindi", name)
            return {"success": True, "data": {"device": name, "ip": ip, **parsed}}

        except Exception as exc:
            last_err = str(exc)
            logger.warning("%s — F5 REST deneme %d basarisiz: %s", name, attempt, exc)
            if attempt < max_retry:
                time.sleep(3)

    return {"success": False, "device": name, "ip": ip,
            "error": last_err or f"{max_retry} deneme basarisiz"}


# ── Fortinet SSH (FAZ/FMG/FAC/FSB/EMS) ile envanter ─────

def _collect_fortinet_ssh(device: dict, credentials: dict, max_retry: int = 3) -> dict:
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
            shell.recv(65535)

            output = _paramiko_send_cmd(shell, "get system status", wait=2)
            conn.close()

            if len(output.strip()) < 50:
                raise ValueError(f"Cok kisa cikti alindi ({len(output)} karakter)")

            parser = get_parser(device["device_type"])
            if not parser:
                raise ValueError(f"Parser bulunamadi: {device['device_type']}")

            parsed = parser(output, device["device_type"])
            logger.info("%s — Fortinet SSH envanter alindi", name)
            return {"success": True, "data": {"device": name, "ip": ip, **parsed}}

        except paramiko.AuthenticationException as exc:
            last_err = str(exc)
            logger.error("%s — SSH auth hatasi: %s", name, exc)
            break
        except Exception as exc:
            last_err = str(exc)
            logger.warning("%s — Fortinet SSH deneme %d basarisiz: %s", name, attempt, exc)
            if attempt < max_retry:
                time.sleep(3)

    return {"success": False, "device": name, "ip": ip,
            "error": last_err or f"{max_retry} deneme basarisiz"}


# ── Bilinmeyen cihaz tipi yeniden tespiti ─────────────────

def _redetect_device_type(device: dict, credentials: dict) -> str | None:
    ip       = device["ip"]
    username = credentials.get("username", "")
    password = credentials.get("password", "")
    if not username or not password:
        return None

    _REDETECT_CHECKS = [
        ("show switch",  [r"system type:", r"sysname:", r"extremexos",
                          r"extreme networks", r"primary ver:\s+\d"],  "extreme_exos"),
        ("show version", [r"extremexos", r"extreme networks"],            "extreme_exos"),
        ("show version", [r"ruijie", r"rgos",
                          r"system software version\s*:"],               "ruijie_os"),
    ]

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, port=22, username=username, password=password,
                       timeout=10, look_for_keys=False, allow_agent=False,
                       banner_timeout=10)
        try:
            shell = client.invoke_shell(width=512, height=9999)
            shell.settimeout(10)
            time.sleep(2)
            banner = shell.recv(65535).decode(errors="replace").lower()
            if "extremexos" in banner or "extreme networks" in banner:
                client.close()
                return "extreme_exos"
            if "ruijie" in banner or "rgos" in banner:
                client.close()
                return "ruijie_os"
        except Exception:
            pass

        for cmd, patterns, dtype in _REDETECT_CHECKS:
            try:
                _, stdout, _ = client.exec_command(cmd, timeout=10)
                out = stdout.read().decode(errors="replace")
                if len(out.strip()) > 10 and any(
                    re.search(p, out, re.IGNORECASE) for p in patterns
                ):
                    client.close()
                    return dtype
            except Exception:
                continue

        client.close()
    except Exception as exc:
        logger.debug("_redetect_device_type basarisiz %s: %s", ip, exc)

    return None


# ── Genel dispatch ────────────────────────────────────────

def _collect_single(device: dict, credentials: dict, max_retry: int = 3) -> dict:
    """
    Cihaz tipine göre uygun toplama fonksiyonuna yönlendirir.

    Dispatch sirasi:
        fortianalyzer / fortimanager / ...  → _collect_fortinet_ssh()  [paramiko]
        fortigate                           → _collect_fortigate()      [REST API]
        f5 / bigip                          → _collect_f5()             [REST API]
        extreme / extreme_exos             → _collect_extreme()        [paramiko]
        ruijie / ruijie_os / rgos          → _collect_ruijie()         [paramiko]
        unknown / ""                        → _redetect + retry
        diger (cisco/huawei/h3c/...)       → _collect_ssh()            [Netmiko]
    """
    dt = device.get("device_type", "").lower()

    if _is_fortinet_ssh(dt):
        return _collect_fortinet_ssh(device, credentials, max_retry)
    if _is_fortigate(dt):
        return _collect_fortigate(device, credentials, max_retry)
    if _is_f5(dt):
        return _collect_f5(device, credentials, max_retry)
    if _is_extreme(dt):
        return _collect_extreme(device, credentials, max_retry)
    if _is_ruijie(dt):
        return _collect_ruijie(device, credentials, max_retry)

    if dt in ("unknown", ""):
        detected = _redetect_device_type(device, credentials)
        if detected:
            logger.info("%s — device_type unknown → %s olarak tespit edildi",
                        device.get("name", device["ip"]), detected)
            device = {**device, "device_type": detected}
            return _collect_single(device, credentials, max_retry)
        msg = f"Cihaz tipi tespit edilemedi: {device['ip']}"
        logger.error("%s — %s", device.get("name", device["ip"]), msg)
        return {"success": False, "device": device.get("name", ""), "ip": device["ip"],
                "error": msg}

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
    print(f"\n  Sonuc kaydedildi: {out_file}")
    logger.info("Envanter sonucu kaydedildi: %s", out_file)


# ── Modül sınıfı ─────────────────────────────────────────

class InventoryCollectorModule(BaseModule):

    def info(self) -> dict[str, str]:
        return {
            "name": "Inventory Collector",
            "description": "Ag cihazlarindan donanim/yazilim envanteri toplar.",
        }

    def run(self, vault: "VaultService | None" = None) -> None:
        v = resolve_vault(vault)
        inventory = _load_inventory()
        tag       = input("  Tag girin (all icin hepsini al): ").strip()
        devices   = _filter_by_tag(inventory, tag)

        if not devices:
            print(f"  {tag!r} tagine sahip cihaz bulunamadi.")
            input("  Enter a basin...")
            return

        print(f"\n  {len(devices)} cihaz islenecek...\n")
        results: list = []
        failed:  list = []

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            future_map: dict = {}
            for device in devices:
                cred_id = device.get("credential_id", "")
                if not cred_id or cred_id not in v.vault:
                    print(f"  [ATLA] {device['name']} — credential bulunamadi")
                    logger.warning("Credential bulunamadi: %s", cred_id)
                    continue
                future_map[
                    pool.submit(_collect_single, device, v.vault[cred_id])
                ] = device

            for future in as_completed(future_map):
                try:
                    res = future.result()
                except Exception as exc:
                    dev = future_map[future]
                    logger.exception("Future hatasi — %s: %s", dev["name"], exc)
                    failed.append({"device": dev["name"], "ip": dev["ip"], "error": str(exc)})
                    continue

                if res["success"]:
                    results.append(res["data"])
                else:
                    failed.append(res)

        _save_results(results, failed)

        print(f"\n  {'─'*44}")
        print(f"  Basarili : {len(results)} / {len(devices)}")
        if failed:
            print(f"  Basarisiz: {len(failed)} / {len(devices)}")
        print(f"  {'─'*44}")

        if failed:
            print(f"\n  Envanter alinamayan cihazlar ({len(failed)}):")
            for idx, d in enumerate(sorted(failed, key=lambda x: x.get("device", "")), start=1):
                print(f"    {idx:>3}. {d.get('device')}  ({d.get('ip')})")
                print(f"         Sebep: {d.get('error')}")
        else:
            print("\n  Tum cihazlardan envanter alindi.")

        input("\n  Enter a basin...")


if __name__ == "__main__":
    InventoryCollectorModule().run()

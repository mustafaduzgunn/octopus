"""
app/modules/network_backup/service.py
──────────────────────────────────────
Karma backup motoru — tek perform_backup() ile üç protokol:

  device_type         Protokol     Kimlik doğrulama
  ──────────────────────────────────────────────────
  fortigate / fortinet REST API    api_token veya user/pass
  bigip / f5           iControl REST  user/pass → X-F5-Auth-Token
  cisco_ios / huawei_* SSH/Netmiko  user/pass

Tüm backup dosyaları aynı günlük klasöre yazılır:
  app/backups/YYYY-MM-DD/
    HH-MM-SS_<name>_<ip>.conf   ← Fortinet
    HH-MM-SS_<name>_<ip>.ucs    ← F5 BIG-IP
    HH-MM-SS_<name>_<ip>.txt    ← SSH (Cisco/Huawei)
"""

from __future__ import annotations

import base64
import getpass
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from enum import Enum, auto
from pathlib import Path

import io
import socket
import threading

import paramiko
import requests
import urllib3
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

_BASE      = Path(__file__).parent.parent.parent
DATA_DIR   = _BASE / "data"
BACKUP_DIR = _BASE / "backups"
VAULT_PATH = DATA_DIR / "vault.dat"

SALT_SIZE         = 16
PBKDF2_ITERATIONS = 200_000
MAX_WORKERS       = 10

# Fortinet REST API ile backup alınan cihazlar (FortiGate ailesi)
_FORTINET_REST_TYPES = {"fortigate", "fortinet"}

# SSH + geçici SFTP sunucusu ile backup alınan Fortinet cihazlar
_FORTINET_SSH_TYPES  = {"fortianalyzer", "fortimanager", "fortiauthenticator",
                         "fortisandbox", "forticlientems", "fortiems"}

# Tüm Fortinet tipleri (REST veya SSH)
_FORTINET_TYPES = _FORTINET_REST_TYPES | _FORTINET_SSH_TYPES

_F5_TYPES       = {"bigip", "f5", "f5_bigip", "big-ip"}

# VELOS F5OS katmanı (System Controller + Chassis Partition) — RESTCONF API
_VELOS_TYPES    = {"velos", "velos_sc", "velos_partition", "f5os"}

_FORTINET_403_HINT = """
    FortiOS 7.4+  → config system accprofile → set mntgrp read-write
    FortiOS 7.2-  → config system accprofile → set sysgrp read-write
    VDOM etkin    → 'config global' altında profil ve api-user oluşturun
"""


# ── Yardımcılar ────────────────────────────────────────────

class BackupResult(Enum):
    SUCCESS   = auto()
    PERMANENT = auto()
    RETRY     = auto()


def _is_fortinet(device: dict) -> bool:
    return any(ft in device.get("device_type", "").lower() for ft in _FORTINET_TYPES)


def _is_fortinet_rest(device: dict) -> bool:
    return any(ft in device.get("device_type", "").lower() for ft in _FORTINET_REST_TYPES)


def _is_fortinet_ssh(device: dict) -> bool:
    return any(ft in device.get("device_type", "").lower() for ft in _FORTINET_SSH_TYPES)


def _is_f5(device: dict) -> bool:
    return any(ft in device.get("device_type", "").lower() for ft in _F5_TYPES)


def _is_velos(device: dict) -> bool:
    """VELOS System Controller veya Chassis Partition — F5OS RESTCONF API."""
    return any(ft in device.get("device_type", "").lower() for ft in _VELOS_TYPES)

def _is_extreme(device: dict) -> bool:
    return "extreme" in device.get("device_type", "").lower()

def _is_ruijie(device: dict) -> bool:
    dt = device.get("device_type", "").lower()
    return "ruijie" in dt or "rgos" in dt


# ── Vault ──────────────────────────────────────────────────

class VaultLoader:
    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=salt,
            iterations=PBKDF2_ITERATIONS, backend=default_backend(),
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    @classmethod
    def load(cls) -> dict:
        if not VAULT_PATH.exists():
            raise FileNotFoundError(f"vault.dat bulunamadı: {VAULT_PATH}")
        data = VAULT_PATH.read_bytes()
        salt, encrypted = data[:SALT_SIZE], data[SALT_SIZE:]
        master = getpass.getpass("Master Password: ")
        key = cls._derive_key(master, salt)
        try:
            return json.loads(Fernet(key).decrypt(encrypted).decode())
        except (InvalidToken, json.JSONDecodeError) as exc:
            raise ValueError("Master password yanlış veya dosya bozuk.") from exc


# ── Inventory / Commands ───────────────────────────────────

def _load_json(path: Path) -> dict | list:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def load_inventory() -> list[dict]:
    return _load_json(DATA_DIR / "inventory.json")  # type: ignore[return-value]


def load_commands() -> dict:
    return _load_json(DATA_DIR / "commands.json")   # type: ignore[return-value]


def get_devices_by_tag(inventory: list[dict], tag: str) -> list[dict]:
    return [d for d in inventory if tag in d.get("tags", [])]


# ── Menü ───────────────────────────────────────────────────

def backup_menu(credentials: dict) -> None:
    inventory     = load_inventory()
    commands_dict = load_commands()

    options: dict[str, tuple[str, object]] = {
        "1": ("Full Backup",       lambda: perform_backup(inventory, credentials, commands_dict)),
        "2": ("Tag'e Göre Backup", lambda: _tagged_backup(inventory, credentials, commands_dict)),
    }

    while True:
        print("\n--- Network Backup ---")
        for key, (label, _) in options.items():
            print(f"  {key} - {label}")
        print("  0 - Ana Menüye Dön")

        choice = input("  Seçiminiz: ").strip()
        if choice == "0":
            break
        if choice in options:
            options[choice][1]()
        else:
            print("  Geçersiz seçim.")


def _tagged_backup(inventory: list[dict], credentials: dict, commands_dict: dict) -> None:
    tag = input("  Tag girin: ").strip()
    if not tag:
        print("  Boş tag girilemez.")
        return
    devices = get_devices_by_tag(inventory, tag)
    if not devices:
        print(f"  '{tag}' tag'ine sahip cihaz bulunamadı.")
        return
    perform_backup(devices, credentials, commands_dict)


# ── Ana backup motoru ──────────────────────────────────────

def perform_backup(
    devices: list[dict],
    credentials: dict,
    commands_dict: dict,
    max_ssh_attempts: int = 3,
) -> None:
    """SSH, Fortinet REST ve F5 iControl REST cihazlarını aynı klasöre yedekler."""
    daily_path = BACKUP_DIR / datetime.now().strftime("%Y-%m-%d")
    daily_path.mkdir(parents=True, exist_ok=True)

    fortinet_rest_devs = [d for d in devices if _is_fortinet_rest(d)]
    fortinet_ssh_devs  = [d for d in devices if _is_fortinet_ssh(d)]
    f5_devs            = [d for d in devices if _is_f5(d)]
    velos_devs         = [d for d in devices if _is_velos(d)]
    paramiko_devs      = [d for d in devices if _is_extreme(d) or _is_ruijie(d)]
    ssh_devs           = [d for d in devices if
                          not _is_fortinet(d) and not _is_f5(d) and not _is_velos(d)
                          and not _is_extreme(d) and not _is_ruijie(d)]

    total        = len(devices)
    success      = 0
    failed       = 0
    failed_names: list[str] = []

    counts = []
    if fortinet_rest_devs: counts.append(f"{len(fortinet_rest_devs)} FortiGate REST")
    if fortinet_ssh_devs:  counts.append(f"{len(fortinet_ssh_devs)} Fortinet SSH")
    if f5_devs:            counts.append(f"{len(f5_devs)} F5 BIG-IP")
    if velos_devs:         counts.append(f"{len(velos_devs)} VELOS F5OS")
    if paramiko_devs:      counts.append(f"{len(paramiko_devs)} SSH (Paramiko)")
    if ssh_devs:           counts.append(f"{len(ssh_devs)} SSH")
    print(f"\n  Toplam {total} cihaz — {', '.join(counts)}\n")

    # ── FortiGate REST API (paralel) ──────────────────────
    if fortinet_rest_devs:
        print(f"  [FortiGate REST] {len(fortinet_rest_devs)} cihaz...")
        s, f, fn = _run_parallel(fortinet_rest_devs, credentials, daily_path, _backup_fortinet)
        success += s; failed += f; failed_names.extend(fn)

    # ── Fortinet SSH (FAZ/FMG/FAC/FSB/EMS — sıralı) ──────
    if fortinet_ssh_devs:
        print(f"\n  [Fortinet SSH] {len(fortinet_ssh_devs)} cihaz (FAZ/FMG/FAC/FSB/EMS)...")
        sftp_ip = _get_local_ip()
        for device in fortinet_ssh_devs:
            cred_id = device.get("credential_id", "")
            if not cred_id or cred_id not in credentials:
                print(f"  [ATLA] {device['name']} — credential bulunamadı: {cred_id}")
                failed += 1
                failed_names.append(device["name"])
                continue
            result = _backup_fortinet_ssh(device, credentials[cred_id], daily_path, sftp_ip)
            if result is BackupResult.SUCCESS:
                success += 1
            else:
                failed += 1
                failed_names.append(device["name"])

    # ── VELOS F5OS (System Controller + Chassis Partition, paralel) ──
    if velos_devs:
        print(f"\n  [VELOS F5OS RESTCONF] {len(velos_devs)} cihaz...")
        s, f, fn = _run_parallel(velos_devs, credentials, daily_path, _backup_velos)
        success += s; failed += f; failed_names.extend(fn)

    # ── F5 iControl REST (paralel) ─────────────────────────
    if f5_devs:
        print(f"\n  [F5 iControl REST] {len(f5_devs)} cihaz...")
        s, f, fn = _run_parallel(f5_devs, credentials, daily_path, _backup_f5)
        success += s; failed += f; failed_names.extend(fn)

    # ── Paramiko SSH (Extreme / Ruijie, retry destekli) ───
    if paramiko_devs:
        print(f"\n  [SSH (Paramiko)] {len(paramiko_devs)} cihaz (Extreme/Ruijie)...")
        remaining_p = list(paramiko_devs)
        for attempt in range(1, max_ssh_attempts + 1):
            if not remaining_p:
                break
            print(f"  Deneme {attempt}/{max_ssh_attempts} — {len(remaining_p)} cihaz")
            retry_list_p: list[dict] = []
            for device in remaining_p:
                result = _backup_paramiko(device, credentials, commands_dict, daily_path)
                if result is BackupResult.SUCCESS:
                    success += 1
                elif result is BackupResult.RETRY:
                    retry_list_p.append(device)
                else:
                    failed += 1
                    failed_names.append(device["name"])
            remaining_p = retry_list_p
        for device in remaining_p:
            print(f"  [BAŞARISIZ] {device['name']} — {max_ssh_attempts} denemede alınamadı")
            logger.error("%s — %d denemede başarısız", device["name"], max_ssh_attempts)
            failed += 1
            failed_names.append(device["name"])

    # ── SSH (Cisco/Huawei, retry destekli) ────────────────
    if ssh_devs:
        print(f"\n  [SSH] {len(ssh_devs)} cihaz...")
        remaining = list(ssh_devs)
        for attempt in range(1, max_ssh_attempts + 1):
            if not remaining:
                break
            print(f"  Deneme {attempt}/{max_ssh_attempts} — {len(remaining)} cihaz")
            retry_list: list[dict] = []
            for device in remaining:
                result = _backup_ssh(device, credentials, commands_dict, daily_path)
                if result is BackupResult.SUCCESS:
                    success += 1
                elif result is BackupResult.RETRY:
                    retry_list.append(device)
                else:
                    failed += 1
                    failed_names.append(device["name"])
            remaining = retry_list
        for device in remaining:
            print(f"  [BAŞARISIZ] {device['name']} — {max_ssh_attempts} denemede alınamadı")
            logger.error("%s — %d denemede başarısız", device["name"], max_ssh_attempts)
            failed += 1
            failed_names.append(device["name"])

    # ── Özet ──────────────────────────────────────────────
    print(f"\n  {'─'*44}")
    print(f"  ✅ Başarılı : {success} / {total}")
    if failed:
        print(f"  ❌ Başarısız: {failed} / {total}")
    print(f"  📁 Klasör   : {daily_path}")
    print(f"  {'─'*44}")

    # ── Backup alınamayan cihazlar ─────────────────────────
    if failed_names:
        print(f"\n  Backup alınamayan cihazlar ({len(failed_names)}):")
        for idx, name in enumerate(sorted(failed_names), start=1):
            print(f"    {idx:>3}. {name}")
        print()

    input("\n  Enter'a basın...")


def _run_parallel(
    devices: list[dict],
    credentials: dict,
    daily_path: Path,
    backup_fn,
    max_attempts: int = 3,
    retry_delay: float = 5.0,
) -> tuple[int, int, list[str]]:
    """Verilen fonksiyonu cihazlar üzerinde paralel çalıştırır.

    BackupResult.RETRY dönen cihazlar max_attempts kez yeniden denenir.
    Bu sayede RADIUS geç cevap verdiğinde bile backup başarılı olabilir.

    Döndürür: (başarılı_sayısı, başarısız_sayısı, başarısız_cihaz_adları)
    """
    success      = failed = 0
    failed_names: list[str] = []
    remaining    = list(devices)

    for attempt in range(1, max_attempts + 1):
        if not remaining:
            break

        retry_devices: list[dict] = []

        if attempt > 1:
            import time as _time
            print(f"  ↻ Yeniden deneme {attempt}/{max_attempts} "
                  f"({len(remaining)} cihaz, {retry_delay:.0f}s bekleniyor...)")
            _time.sleep(retry_delay)

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            future_map: dict = {}
            for device in remaining:
                cred_id = device.get("credential_id", "")
                if not cred_id or cred_id not in credentials:
                    print(f"  [ATLA] {device['name']} — credential bulunamadı: {cred_id}")
                    failed += 1
                    failed_names.append(device["name"])
                    continue
                future_map[
                    pool.submit(backup_fn, device, credentials[cred_id], daily_path)
                ] = device

            for future in as_completed(future_map):
                device = future_map[future]
                try:
                    result = future.result()
                    if result is BackupResult.SUCCESS:
                        success += 1
                    elif result is BackupResult.RETRY:
                        retry_devices.append(device)   # tekrar dene
                    else:
                        failed += 1                    # PERMANENT — tekrar deneme
                        failed_names.append(device["name"])
                except Exception as exc:
                    logger.exception("%s — backup hatası: %s", device["name"], exc)
                    failed += 1
                    failed_names.append(device["name"])

        remaining = retry_devices

    # max_attempts sonunda hâlâ başarısız olanlar
    for device in remaining:
        print(f"  [BAŞARISIZ] {device['name']} — {max_attempts} denemede alınamadı")
        logger.error("%s — %d denemede başarısız", device["name"], max_attempts)
        failed += 1
        failed_names.append(device["name"])

    return success, failed, failed_names


# ── Yardımcı: Yerel IP ────────────────────────────────────

def _get_local_ip() -> str:
    """Cihazların ulaşabileceği yerel IP adresini tespit eder."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


# ── Geçici bellek-içi SFTP sunucusu ───────────────────────

class _MemorySFTPHandle(paramiko.SFTPHandle):
    """Gelen dosyayı bellekte tutan SFTP dosya handle'ı."""

    def __init__(self, buf: io.BytesIO) -> None:
        super().__init__(paramiko.SFTP_FLAG_WRITE | paramiko.SFTP_FLAG_CREATE)
        self._buf = buf

    def write(self, offset: int, data: bytes) -> int:
        self._buf.seek(offset)
        self._buf.write(data)
        return paramiko.SFTP_OK


class _MemorySFTPServer(paramiko.SFTPServerInterface):
    """Tek bir dosyayı bellekte kabul eden minimal SFTP sunucusu."""

    def __init__(self, *args, received: dict, expected_filename: str, **kwargs):
        super().__init__(*args, **kwargs)
        self._received         = received          # {"data": bytes | None}
        self._expected_filename = expected_filename

    def open(self, path: str, flags: int, attr: paramiko.SFTPAttributes):
        buf = io.BytesIO()
        handle = _MemorySFTPHandle(buf)
        handle.filename = path
        self._received["buf"] = buf
        return handle

    def close(self):
        if "buf" in self._received:
            self._received["data"] = self._received["buf"].getvalue()

    def stat(self, path: str):
        attr = paramiko.SFTPAttributes()
        attr.st_size = 0
        return attr

    def lstat(self, path: str):
        return self.stat(path)

    def list_folder(self, path: str):
        return []

    def mkdir(self, path: str, attr):
        return paramiko.SFTP_OK

    def remove(self, path: str):
        return paramiko.SFTP_OK

    def rename(self, oldpath: str, newpath: str):
        return paramiko.SFTP_OK


def _run_sftp_server(
    host_key: paramiko.RSAKey,
    port: int,
    sftp_user: str,
    sftp_pass: str,
    received: dict,
    expected_filename: str,
    timeout: float = 90.0,
) -> None:
    """
    Tek bağlantı kabul eden geçici SFTP sunucusu.
    Thread içinde çalışır, bağlantı kapanınca veya timeout'ta durur.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(timeout)
    sock.bind(("0.0.0.0", port))
    sock.listen(1)

    try:
        conn, _ = sock.accept()
    except socket.timeout:
        received["error"] = "SFTP sunucusu bağlantı beklerken zaman aşımı"
        return
    finally:
        sock.close()

    transport = paramiko.Transport(conn)
    transport.add_server_key(host_key)
    transport.set_subsystem_handler(
        "sftp",
        paramiko.SFTPServer,
        sftp_si=_MemorySFTPServer,
        received=received,
        expected_filename=expected_filename,
    )

    class _AuthServer(paramiko.ServerInterface):
        def check_auth_password(self, username, password):
            if username == sftp_user and password == sftp_pass:
                return paramiko.AUTH_SUCCESSFUL
            return paramiko.AUTH_FAILED

        def check_channel_request(self, kind, chanid):
            return paramiko.OPEN_SUCCEEDED

        def get_allowed_auths(self, username):
            return "password"

    server = _AuthServer()
    try:
        transport.start_server(server=server)
        channel = transport.accept(timeout)
        if channel:
            channel.event.wait(timeout)
    except Exception:
        pass
    finally:
        transport.close()
        conn.close()

    # SFTP handle close() çağrılmamış olabilir — buf'u kopyala
    if "buf" in received and "data" not in received:
        received["data"] = received["buf"].getvalue()


# ── Fortinet SSH backup (FAZ/FMG/FAC/FSB/EMS) ─────────────
#
# Cihaz tipine göre iki strateji:
#
# FAZ / FMG → PUSH: execute backup all-settings sftp ...
#   - Tek gerçek backup yolu (GUI ile aynı boyut)
#   - Octopus'ta paramiko ile geçici SFTP sunucusu açılır
#   - Cihaz backup dosyasını Octopus'a gönderir
#   - inventory.json'da "sftp_port" tanımlanmalı (default: 2222)
#   - Güvenlik duvarı: cihazın Octopus IP:sftp_port'a erişimi olmalı
#
# FAC / FSB / EMS → PULL: SSH shell → show komutu çıktısı alınır
#   - Tek yönlü bağlantı, push gerektirmez
#   - Boyut FAZ'a göre çok küçük (birkaç KB)

_SSH_TIMEOUT    = 120   # saniye
_SFTP_BASE_PORT = 2222  # FAZ/FMG için varsayılan SFTP port
_SFTP_USER      = "octopus_sftp"
_SFTP_PASS      = "OctopusSFTP!2024"

# Pull stratejisi uygulanan cihaz tipleri (küçük config, show ile alınabilir)
_FORTINET_PULL_TYPES = {"fortiauthenticator", "fortisandbox", "forticlientems", "fortiems"}

# Push stratejisi uygulanan cihaz tipleri (büyük backup, SFTP gerektirir)
_FORTINET_PUSH_TYPES = {"fortianalyzer", "fortimanager"}


def _is_fortinet_push(device_type: str) -> bool:
    return any(t in device_type.lower() for t in _FORTINET_PUSH_TYPES)


def _backup_fortinet_ssh(
    device: dict,
    cred: dict,
    daily_path: Path,
    sftp_ip: str = "",
) -> BackupResult:
    """FAZ/FMG → SFTP push, FAC/FSB/EMS → SSH pull."""
    device_type = device.get("device_type", "").lower()
    if _is_fortinet_push(device_type):
        return _backup_fortinet_ssh_push(device, cred, daily_path, sftp_ip)
    return _backup_fortinet_ssh_pull(device, cred, daily_path)


# ── FAZ / FMG: SFTP Push ──────────────────────────────────

def _backup_fortinet_ssh_push(
    device: dict,
    cred: dict,
    daily_path: Path,
    sftp_ip: str = "",
) -> BackupResult:
    """
    FortiAnalyzer / FortiManager backup:
      execute backup all-settings sftp <octopus_ip>:<port> <dosya> <user> <pass> "" ""

    Paramiko ile geçici SFTP sunucusu açılır, cihaz dosyayı push'lar.

    inventory.json alanları:
      "sftp_port": 2222          (varsayılan, her cihaz için farklı olmalı)
      "sftp_encrypt_pass": ""    (FAZ backup şifreleme, boş bırakılabilir)
    """
    name            = device["name"]
    ip              = device["ip"]
    ssh_port        = device.get("port", 22)
    device_type     = device.get("device_type", "").lower()
    username        = cred.get("username", "")
    password        = cred.get("password", "")
    sftp_port       = device.get("sftp_port", _SFTP_BASE_PORT)
    sftp_encrypt_pw = device.get("sftp_encrypt_pass", "")
    local_ip        = sftp_ip or _get_local_ip()

    ts       = datetime.now().strftime("%H-%M-%S")
    filename = f"{ts}_{name}_{ip}.dat"

    # execute backup all-settings sftp <ip:port> <file> <user> <pass> <ssh-cert> <crptpasswd>
    cmd = (
        f'execute backup all-settings sftp {local_ip}:{sftp_port} '
        f'{filename} {_SFTP_USER} {_SFTP_PASS} "" "{sftp_encrypt_pw}"'
    )

    received: dict = {}
    host_key = paramiko.RSAKey.generate(2048)

    sftp_thread = threading.Thread(
        target=_run_sftp_server,
        kwargs=dict(
            host_key         = host_key,
            port             = sftp_port,
            sftp_user        = _SFTP_USER,
            sftp_pass        = _SFTP_PASS,
            received         = received,
            expected_filename= filename,
            timeout          = _SSH_TIMEOUT,
        ),
        daemon=True,
    )
    sftp_thread.start()
    time.sleep(1.5)   # sunucunun bind() yapmasını bekle

    try:
        conn = paramiko.SSHClient()
        conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        conn.connect(ip, port=ssh_port, username=username, password=password,
                     timeout=30, look_for_keys=False, allow_agent=False)

        stdin, stdout, stderr = conn.exec_command(cmd, timeout=_SSH_TIMEOUT)
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        conn.close()
        logger.debug("%s — FAZ backup komutu çıktısı: %s | hata: %s", name, out[:300], err[:200])

    except paramiko.AuthenticationException:
        sftp_thread.join(timeout=3)
        print(f"  [AUTH HATA] {name} — SSH kimlik doğrulama başarısız (yeniden denenecek)")
        logger.warning("%s — SSH auth hatası (RETRY)", name)
        return BackupResult.RETRY
    except Exception as exc:
        sftp_thread.join(timeout=3)
        print(f"  [SSH HATA] {name} — {exc}")
        logger.error("%s — SSH bağlantı hatası: %s", name, exc)
        return BackupResult.RETRY

    sftp_thread.join(timeout=_SSH_TIMEOUT + 10)

    if "error" in received:
        print(f"  [SFTP HATA] {name} — {received['error']}")
        print(f"    Cihazın Octopus makinenize ({local_ip}:{sftp_port}) TCP erişimi var mı?")
        print(f"    Kontrol: FAZ üzerinde  execute ping {local_ip}")
        logger.error("%s — SFTP sunucu hatası: %s", name, received["error"])
        return BackupResult.RETRY

    data = received.get("data")
    if not data or len(data) < 1024:
        print(f"  [HATA] {name} — veri gelmedi veya çok küçük ({len(data) if data else 0} byte)")
        print(f"    SFTP sunucu portu ({sftp_port}) Windows Güvenlik Duvarı'nda açık mı?")
        logger.error("%s — SFTP veri yetersiz", name)
        return BackupResult.RETRY

    out_path = daily_path / filename
    out_path.write_bytes(data)
    size = out_path.stat().st_size
    print(f"  [OK] {name}  ({size:,} byte)  →  {out_path.name}")
    logger.info("%s — FAZ/FMG SFTP push backup başarılı (%d byte)", name, size)
    return BackupResult.SUCCESS


# ── FAC / FSB / EMS: SSH Pull ─────────────────────────────

_FORTINET_PULL_CMDS: dict[str, str] = {
    "fortiauthenticator": "show",
    "fortisandbox":       "show",
    "forticlientems":     "show",
    "fortiems":           "show",
}


def _backup_fortinet_ssh_pull(
    device: dict,
    cred: dict,
    daily_path: Path,
) -> BackupResult:
    """FortiAuthenticator / FortiSandbox / EMS — SSH shell + show komutu."""
    name        = device["name"]
    ip          = device["ip"]
    ssh_port    = device.get("port", 22)
    device_type = device.get("device_type", "").lower()
    username    = cred.get("username", "")
    password    = cred.get("password", "")

    pull_cmd = next(
        (cmd for key, cmd in _FORTINET_PULL_CMDS.items() if key in device_type),
        "show",
    )

    try:
        conn = paramiko.SSHClient()
        conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        conn.connect(ip, port=ssh_port, username=username, password=password,
                     timeout=30, look_for_keys=False, allow_agent=False)

        shell = conn.invoke_shell(width=512, height=9999)
        shell.settimeout(_SSH_TIMEOUT)
        time.sleep(2)
        shell.recv(65535)  # banner temizle

        shell.send(pull_cmd + "\n")
        time.sleep(2)

        parts: list[str] = []
        deadline = time.time() + _SSH_TIMEOUT
        while time.time() < deadline:
            if shell.recv_ready():
                chunk = shell.recv(65535).decode(errors="replace")
                if "-- More --" in chunk or "--More--" in chunk:
                    shell.send(" ")
                    time.sleep(0.2)
                parts.append(chunk)
                time.sleep(0.3)
            else:
                time.sleep(2)
                if not shell.recv_ready():
                    break

        conn.close()
        config_text = "".join(parts)

        if len(config_text.strip()) < 100:
            print(f"  [HATA] {name} — config çıktısı çok kısa ({len(config_text)} karakter)")
            return BackupResult.RETRY

        ts       = datetime.now().strftime("%H-%M-%S")
        out_path = daily_path / f"{ts}_{name}_{ip}.conf"
        out_path.write_text(config_text, encoding="utf-8", errors="replace")
        size = out_path.stat().st_size
        print(f"  [OK] {name}  ({size:,} byte)  →  {out_path.name}")
        logger.info("%s — SSH pull backup başarılı (%d byte)", name, size)
        return BackupResult.SUCCESS

    except paramiko.AuthenticationException:
        print(f"  [AUTH HATA] {name} — SSH kimlik doğrulama başarısız (yeniden denenecek)")
        logger.warning("%s — SSH auth hatası (RETRY)", name)
        return BackupResult.RETRY
    except Exception as exc:
        print(f"  [SSH HATA] {name} — {exc}")
        logger.error("%s — SSH pull hatası: %s", name, exc)
        return BackupResult.RETRY


# ── VELOS F5OS RESTCONF backup ─────────────────────────────
#
# VELOS mimarisinde 3 katman vardır, hepsi ayrı backup ister:
#   1. System Controller  → port 8888, /restconf/data/f5-database:config-backup
#   2. Chassis Partition  → port 8888, aynı endpoint, farklı IP
#   3. Tenant (BIG-IP)    → normal iControl REST UCS backup (_backup_f5)
#
# inventory.json'da device_type:
#   "velos_sc"        → System Controller
#   "velos_partition" → Chassis Partition
#   "velos" veya "f5os" → her ikisi de denenebilir
#
# Auth: Basic auth varsayılan kapalı, X-Auth-Token kullanılır.
# Token: GET https://<ip>:8888/restconf/data/openconfig-system:system/aaa
#        Authorization: Basic <base64(user:pass)>
#        Yanıt header'ında X-Auth-Token gelir.

_VELOS_PORT    = 8888
_VELOS_TIMEOUT = 30


def _get_velos_token(
    session: requests.Session,
    base_url: str,
    username: str,
    password: str,
) -> str:
    """VELOS F5OS RESTCONF token alır.

    F5OS Basic auth'u varsayılan devre dışıdır.
    Token alma akışı (resmi dokümana göre):
      HEAD /restconf/data/openconfig-system:system/aaa
      Header: Authorization: Basic <b64>
      Header: X-Auth-Token: rctoken   ← sabit placeholder
      Yanıt header'ı: X-Auth-Token: <gerçek_token>
    """
    import base64
    b64 = base64.b64encode(f"{username}:{password}".encode()).decode()
    aaa_url = f"{base_url}/restconf/data/openconfig-system:system/aaa"

    # Yöntem 1: HEAD + placeholder token (resmi F5OS yöntemi)
    try:
        resp = session.request(
            "HEAD",
            aaa_url,
            headers={
                "Authorization": f"Basic {b64}",
                "Content-Type": "application/yang-data+json",
                "X-Auth-Token": "rctoken",   # placeholder — sunucu gerçek token'ı yanıtlar
            },
            timeout=_VELOS_TIMEOUT,
            verify=False,
        )
        token = resp.headers.get("X-Auth-Token", "")
        if token and token != "rctoken":
            logger.debug("VELOS token alındı (HEAD yöntemi)")
            return token
    except Exception as exc:
        logger.debug("VELOS HEAD token hatası: %s", exc)

    # Yöntem 2: GET — bazı F5OS versiyonlarında çalışır
    try:
        resp = session.get(
            aaa_url,
            headers={
                "Authorization": f"Basic {b64}",
                "Content-Type": "application/yang-data+json",
            },
            timeout=_VELOS_TIMEOUT,
            verify=False,
        )
        token = resp.headers.get("X-Auth-Token", "")
        if token:
            logger.debug("VELOS token alındı (GET yöntemi)")
            return token
    except Exception as exc:
        logger.debug("VELOS GET token hatası: %s", exc)

    return ""


def _backup_velos(device: dict, cred: dict, daily_path: Path) -> BackupResult:
    """
    VELOS F5OS System Controller veya Chassis Partition backup akışı:
      1. AAA endpoint'inden X-Auth-Token al (Basic auth ile)
      2. POST config-backup → backup dosyasını F5OS'ta oluştur
      3. POST start-download → dosyayı HTTP response olarak al
      4. Lokale yaz

    inventory.json örneği:
      {"name": "VELOS-SC", "ip": "10.0.0.100", "device_type": "velos_sc",
       "port": 8888, "credential_id": "velos-cred"}
      {"name": "VELOS-PART1", "ip": "10.0.0.101", "device_type": "velos_partition",
       "port": 8888, "credential_id": "velos-cred"}
    """
    name     = device["name"]
    ip       = device["ip"]
    port     = device.get("port", _VELOS_PORT)
    username = cred.get("username", "")
    password = cred.get("password", "")

    base_url = f"https://{ip}:{port}"
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    bak_name = f"octopus_{name}_{ts}"

    try:
        session = requests.Session()
        session.verify = False

        # 1. Token al
        token = _get_velos_token(session, base_url, username, password)
        if not token:
            print(f"  [AUTH HATA] {name} — VELOS token alınamadı")
            logger.error("%s — VELOS token alınamadı", name)
            return BackupResult.RETRY

        headers = {
            "X-Auth-Token": token,
            "Content-Type": "application/yang-data+json",
        }

        # 2. Config backup oluştur
        backup_resp = session.post(
            f"{base_url}/restconf/data/openconfig-system:system/"
            "f5-database:database/f5-database:config-backup",
            headers=headers,
            json={"f5-database:name": bak_name, "f5-database:overwrite": "true"},
            timeout=60,
        )
        if backup_resp.status_code not in (200, 201, 204):
            print(f"  [HATA] {name} — backup oluşturulamadı (HTTP {backup_resp.status_code})")
            logger.error("%s — VELOS config-backup HTTP %d", name, backup_resp.status_code)
            return BackupResult.RETRY

        time.sleep(3)   # backup oluşturulması için bekle

        # 3. Dosyayı indir
        dl_resp = session.post(
            f"{base_url}/restconf/data/f5-utils-file-transfer:file/"
            "f5-file-download:download-file/f5-file-download:start-download",
            headers=headers,
            data=f"path=configs/{bak_name}\nlocal-file=configs/{bak_name}",
            timeout=60,
            stream=True,
        )

        if dl_resp.status_code not in (200, 201):
            # İndirme endpoint farklı formatta olabilir — form-data dene
            import base64
            dl_resp = session.post(
                f"{base_url}/restconf/data/f5-utils-file-transfer:file/"
                "f5-file-download:download-file/f5-file-download:start-download",
                headers={**headers, "Content-Type": "multipart/form-data"},
                files={
                    "path": (None, f"configs/{bak_name}"),
                    "local-file": (None, f"configs/{bak_name}"),
                },
                timeout=60,
                stream=True,
            )

        if dl_resp.status_code not in (200, 201):
            print(f"  [HATA] {name} — VELOS dosya indirilemedi (HTTP {dl_resp.status_code})")
            logger.error("%s — VELOS download HTTP %d", name, dl_resp.status_code)
            return BackupResult.RETRY

        ts_file  = datetime.now().strftime("%H-%M-%S")
        out_path = daily_path / f"{ts_file}_{name}_{ip}.xml"
        with open(out_path, "wb") as fh:
            for chunk in dl_resp.iter_content(chunk_size=8192):
                fh.write(chunk)

        size = out_path.stat().st_size
        if size < 100:
            out_path.unlink(missing_ok=True)
            print(f"  [HATA] {name} — indirilen dosya çok küçük ({size} byte)")
            return BackupResult.RETRY

        print(f"  [OK] {name}  ({size:,} byte)  →  {out_path.name}")
        logger.info("%s — VELOS F5OS backup başarılı (%d byte)", name, size)
        return BackupResult.SUCCESS

    except requests.HTTPError as exc:
        print(f"  [HTTP HATA] {name} — {exc}")
        logger.error("%s — VELOS HTTP hatası: %s", name, exc)
        return BackupResult.RETRY
    except Exception as exc:
        print(f"  [HATA] {name} — {exc}")
        logger.error("%s — VELOS backup hatası: %s", name, exc)
        return BackupResult.RETRY




# ── Fortinet REST backup ───────────────────────────────────


def _get_f5_providers(session: requests.Session, base_url: str) -> list[str]:
    """F5 üzerindeki auth provider listesini çeker.

    Returns:
        Provider adları listesi. Erişilemezse varsayılan liste döner.
    """
    try:
        resp = session.get(
            f"{base_url}/mgmt/tm/auth/source",
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            # 'type' alanı aktif auth kaynağını gösterir (local, radius, ldap, tacacs)
            source_type = data.get("type", "local")
            logger.debug("F5 auth source type: %s", source_type)
    except Exception:
        pass

    # Provider'ları dene — önce tmos (local), sonra remote provider adları
    # inventory.json'da "login_provider" tanımlanmışsa o kullanılır
    return ["tmos", "local"]


def _get_f5_token(
    session: requests.Session,
    base_url: str,
    username: str,
    password: str,
    login_provider: str = "",
) -> tuple[str, str]:
    """F5 iControl REST token alır.

    BIG-IP 17.x token endpoint davranışı:
      - POST /mgmt/shared/authn/login
      - ZORUNLU: Authorization: Basic <base64> header
      - ZORUNLU: JSON body { username, password, loginProviderName }
      - İkisi birlikte gönderilmezse 401 döner

    Strateji (sırayla denenir, ilk başarılı olanla devam edilir):
      1. Basic auth header + provider="tmos"   (local kullanıcılar, çoğu sürüm)
      2. Basic auth header + provider="local"  (bazı BIG-IP sürümleri)
      3. inventory.json'da login_provider tanımlıysa onu da dene
      4. Basic auth header olmadan JSON-only (eski BIG-IP sürümleri)

    Şifredeki !.*@ gibi özel karakterler Python requests tarafından
    her zaman doğru iletilir — shell escape sorunu yaşanmaz.

    Returns:
        (token, kullanılan_provider) veya ("", "") başarısızsa.
    """
    login_url = f"{base_url}/mgmt/shared/authn/login"

    # Denenecek (provider, basic_auth_header) kombinasyonları
    attempts: list[tuple[str, bool]] = [
        ("tmos", True),    # BIG-IP 12-17 local kullanıcılar — standart yol
        ("local", True),   # bazı sürümler "local" ister
    ]

    # inventory.json'da özel provider tanımlıysa listeye ekle
    if login_provider and login_provider not in ("tmos", "local"):
        attempts.insert(0, (login_provider, True))

    # Son çare: Basic auth header olmadan (eski sürümler için)
    attempts.append(("tmos", False))

    import base64, json as _json

    for provider, with_basic in attempts:
        body_dict = {"username": username, "password": password, "loginProviderName": provider}
        body_bytes = _json.dumps(body_dict).encode("utf-8")

        # Content-Type ve Authorization header'ı elle set et
        # (session üzerindeki headers ile çakışmayı önlemek için)
        headers = {"Content-Type": "application/json"}
        if with_basic:
            token_b64 = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
            headers["Authorization"] = f"Basic {token_b64}"

        try:
            # auth= parametresi KULLANILMIYOR — elle header ekliyoruz
            # Böylece session headers ile çakışma olmaz
            resp = session.post(
                login_url,
                data=body_bytes,      # json= yerine data= — encoding kesinleşti
                headers=headers,
                timeout=15,
            )
            if resp.status_code == 200:
                token = resp.json().get("token", {}).get("token", "")
                if token:
                    label = f"provider={provider}, basic={'evet' if with_basic else 'hayır'}"
                    logger.debug("F5 token alındı (%s)", label)
                    return token, provider
            logger.debug(
                "F5 login başarısız: provider=%s, basic=%s, status=%d — yanıt: %s",
                provider, with_basic, resp.status_code, resp.text[:200],
            )
        except Exception as exc:
            logger.debug("F5 login exception provider=%s: %s", provider, exc)

    return "", ""


def _backup_fortinet(device: dict, cred: dict, daily_path: Path) -> BackupResult:
    """
    FortiGate tam konfigurasyon yedeği.

    Strateji sırası:
      1. REST API  — GET /backup?destination=file&scope=global
         Tam binary .conf dosyası, GUI ile özdeş.
         resp.content HER ZAMAN alınır (Content-Type'a bakılmaz).
      2. SSH show full-configuration
         REST çalışmadığında veya küçük dosya (<500KB) geldiğinde devreye girer.
         'show full-configuration' tüm policy, route, object, VPN, user tanımlarını içerir.
    """
    import gzip as _gzip
    import paramiko as _pm
    import time as _time

    name      = device["name"]
    ip        = device["ip"]
    port      = device.get("port", 443)
    ssh_port  = 22
    api_token = cred.get("api_token", "")
    username  = cred.get("username", "")
    password  = cred.get("password", "")
    vdom      = device.get("vdom", "")

    config_text: str | None = None

    # ── Strateji 1: REST API ───────────────────────────────
    try:
        session = requests.Session()
        session.verify = False
        session.headers["Accept"] = "*/*"

        if api_token:
            session.headers["Authorization"] = f"Bearer {api_token}"
            extra = {"access_token": api_token}
        else:
            r = session.post(
                f"https://{ip}:{port}/logincheck",
                data={"username": username, "secretkey": password},
                timeout=15,
            )
            r.raise_for_status()
            csrf = r.cookies.get("ccsrftoken", "").strip('"')
            if csrf:
                session.headers["X-CSRFTOKEN"] = csrf
            extra = {}

        scope = {"scope": "vdom", "vdom": vdom} if (
            vdom and vdom.lower() not in ("", "global", "root")
        ) else {"scope": "global"}

        params = {**scope, **extra, "destination": "file"}
        resp = session.get(
            f"https://{ip}:{port}/api/v2/monitor/system/config/backup",
            params=params,
            timeout=60,
            stream=True,
        )
        session.close()

        if resp.status_code == 403:
            logger.warning("%s — REST 403, SSH stratejisine geçiliyor", name)
        elif resp.status_code == 200:
            raw = resp.content
            # Gzip açma
            if raw[:2] == b"\x1f\x8b":
                try:
                    raw = _gzip.decompress(raw)
                except Exception:
                    pass
            # JSON gelirse (bazı FortiOS sürümleri) içinden config alanını çek
            candidate = raw.decode("utf-8", errors="replace")
            if candidate.strip().startswith("{"):
                try:
                    import json as _json
                    jdata   = _json.loads(raw)
                    results = jdata.get("results", jdata)
                    candidate = (results.get("config") or
                                 results.get("data")   or "")
                except Exception:
                    candidate = ""
            # Boyut ve içerik kontrolü: 500 KB altındaysa güvenilmez, SSH fallback
            if (len(candidate.strip()) > 500_000 and
                    any(k in candidate for k in ("config firewall policy",
                                                  "config system interface",
                                                  "config router"))):
                config_text = candidate
                logger.info("%s — REST backup OK (%d byte)", name, len(candidate))
            else:
                logger.warning(
                    "%s — REST backup küçük/eksik (%d byte), SSH deneniyor",
                    name, len(candidate),
                )

    except Exception as exc:
        logger.warning("%s — REST hatası (%s), SSH deneniyor", name, exc)

    # ── Strateji 2: SSH show full-configuration ────────────
    if not config_text:
        try:
            client = _pm.SSHClient()
            client.set_missing_host_key_policy(_pm.AutoAddPolicy())
            client.connect(
                ip, port=ssh_port,
                username=username, password=password,
                timeout=30,
                look_for_keys=False, allow_agent=False,
            )

            shell = client.invoke_shell(width=512, height=9999)
            shell.settimeout(120)
            _time.sleep(2)
            shell.recv(65535)           # banner temizle

            # Global scope için önce 'config global' yap (VDOM modunda gerekli)
            shell.send("config global\n")
            _time.sleep(1)
            if shell.recv_ready():
                shell.recv(65535)

            shell.send("show full-configuration\n")
            _time.sleep(3)

            parts: list[str] = []
            deadline = _time.time() + 120   # 2 dakika timeout
            last_recv = _time.time()
            while _time.time() < deadline:
                if shell.recv_ready():
                    chunk = shell.recv(65535).decode(errors="replace")
                    parts.append(chunk)
                    last_recv = _time.time()
                    # More prompt'unu atla
                    if "--More--" in chunk or "-- More --" in chunk:
                        shell.send(" ")
                    _time.sleep(0.1)
                else:
                    # 3 saniye veri gelmediyse bitti say
                    if _time.time() - last_recv > 3:
                        break
                    _time.sleep(0.5)

            client.close()
            raw_text = "".join(parts)

            # ANSI escape temizle
            import re as _re
            raw_text = _re.sub(r"\x1b\[[0-9;]*[mK]", "", raw_text)
            raw_text = _re.sub(r"\x1b\[H\x1b\[2J", "", raw_text)   # clear screen
            raw_text = _re.sub(r"--More--|-- More --", "", raw_text)

            if (len(raw_text.strip()) > 1000 and
                    "config" in raw_text and "end" in raw_text):
                config_text = raw_text
                logger.info("%s — SSH backup OK (%d byte)", name, len(raw_text))
            else:
                raise ValueError(
                    f"SSH çıktısı yetersiz ({len(raw_text)} karakter)"
                )

        except _pm.AuthenticationException:
            logger.error("%s — SSH auth hatası", name)
            return BackupResult.PERMANENT
        except Exception as exc:
            logger.error("%s — SSH backup hatası: %s", name, exc)
            if not config_text:
                print(f"  [HATA] {name} — Her iki strateji başarısız: {exc}")
                return BackupResult.RETRY

    # ── Dosyaya yaz ────────────────────────────────────────
    if not config_text or len(config_text.strip()) < 100:
        print(f"  [HATA] {name} — Geçerli config alınamadı")
        return BackupResult.RETRY

    ts   = datetime.now().strftime("%H-%M-%S")
    path = daily_path / f"{ts}_{name}_{ip}.conf"
    path.write_text(config_text, encoding="utf-8", errors="replace")
    size = path.stat().st_size

    print(f"  [OK] {name}  ({size:,} byte)  →  {path.name}")
    logger.info("%s — Fortinet backup başarılı (%d byte)", name, size)
    return BackupResult.SUCCESS

# ── F5 iControl REST backup ────────────────────────────────

def _backup_f5(device: dict, cred: dict, daily_path: Path) -> BackupResult:
    """
    F5 BIG-IP UCS backup akışı:
      1. Token al — tmos / local / Basic auth sırayla denenir
      2. POST /mgmt/tm/sys/ucs  → UCS oluştur
      3. GET  /mgmt/shared/file-transfer/ucs-downloads/<dosya>  → indir
      4. DELETE /mgmt/tm/sys/ucs/<dosya>  → geçici dosyayı temizle
    """
    name           = device["name"]
    ip             = device["ip"]
    port           = device.get("port", 443)
    username       = cred.get("username", "")
    password       = cred.get("password", "")
    login_provider = device.get("login_provider", "")

    base_url = f"https://{ip}:{port}"
    ucs_name = f"octopus_{name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.ucs"

    try:
        session = requests.Session()
        session.verify = False
        session.headers.update({"Content-Type": "application/json"})

        # 1. Token al — birden fazla provider ve Basic auth sırayla denenir
        token, used_provider = _get_f5_token(session, base_url, username, password, login_provider)

        if not token:
            providers_tried = [login_provider] if login_provider else ["tmos", "local", "basic"]
            print(f"  [AUTH HATA] {name} — giriş başarısız (yeniden denenecek)")
            print(f"    Provider'lar: {', '.join(providers_tried)}")
            logger.warning("%s — F5 token alınamadı (RETRY), provider'lar: %s", name, providers_tried)
            # RETRY: RADIUS geç cevap vermiş olabilir, sonraki turda tekrar denenir
            return BackupResult.RETRY

        if token != "BASIC_AUTH":
            session.headers.update({"X-F5-Auth-Token": token})
        logger.debug("%s — F5 giriş başarılı (provider: %s)", name, used_provider)

        # 2. BIG-IP üzerinde UCS dosyası oluştur
        save_resp = session.post(
            f"{base_url}/mgmt/tm/sys/ucs",
            json={"command": "save", "name": ucs_name},
            timeout=120,
        )
        save_resp.raise_for_status()
        time.sleep(3)

        # 3. UCS dosyasını indir
        dl_resp = session.get(
            f"{base_url}/mgmt/shared/file-transfer/ucs-downloads/{ucs_name}",
            timeout=120,
            stream=True,
        )
        dl_resp.raise_for_status()

        ts   = datetime.now().strftime("%H-%M-%S")
        path = daily_path / f"{ts}_{name}_{ip}.ucs"
        with open(path, "wb") as fh:
            for chunk in dl_resp.iter_content(chunk_size=8192):
                fh.write(chunk)

        file_size = path.stat().st_size
        if file_size < 1024:
            path.unlink(missing_ok=True)
            raise ValueError(f"İndirilen UCS dosyası çok küçük ({file_size} byte)")

        # 4. BIG-IP üzerindeki geçici UCS'i temizle
        try:
            session.delete(f"{base_url}/mgmt/tm/sys/ucs/{ucs_name}", timeout=15)
        except Exception:
            pass

        session.close()

        print(f"  [OK] {name}  ({file_size:,} byte)  →  {path.name}")
        logger.info("%s — F5 UCS backup başarılı (provider: %s)", name, used_provider)
        return BackupResult.SUCCESS

    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "?"
        print(f"  [HTTP {status}] {name} — {exc}")
        logger.error("%s — F5 HTTP hatası %s: %s", name, status, exc)
        return BackupResult.PERMANENT if status in (401, 403) else BackupResult.RETRY

    except Exception as exc:
        print(f"  [HATA] {name} — {exc}")
        logger.error("%s — F5 backup hatası: %s", name, exc)
        return BackupResult.RETRY


# ── Paramiko backup (Extreme/Ruijie) ──────────────────────

def _backup_paramiko(
    device: dict, credentials: dict, commands_dict: dict, daily_path: Path
) -> BackupResult:
    """
    Extreme Networks ExtremeXOS ve Ruijie RGOS cihazları için paramiko
    interactive shell üzerinden config backup alır.

    Netmiko bu cihaz tipleriyle uyumsuz olduğundan doğrudan paramiko kullanılır.
    Komutlar commands.json'daki backup → device_type listesinden gelir:
        extreme_exos : ["show configuration"]
        ruijie_os    : ["show running-config"]
    """
    name        = device["name"]
    ip          = device["ip"]
    device_type = device["device_type"]
    cred_id     = device.get("credential_id", "")

    if cred_id not in credentials:
        print(f"  [HATA] {name} — credential bulunamadı ({cred_id})")
        logger.error("%s — credential yok: %s", name, cred_id)
        return BackupResult.PERMANENT

    cred = credentials[cred_id]
    cmds: list[str] = commands_dict.get("backup", {}).get(device_type, [])

    if not cmds:
        print(f"  [HATA] {name} — {device_type} için komut tanımlı değil")
        logger.error("%s — komut yok: %s", name, device_type)
        return BackupResult.PERMANENT

    try:
        conn = paramiko.SSHClient()
        conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        conn.connect(
            ip, port=device.get("port", 22),
            username=cred.get("username", ""),
            password=cred.get("password", ""),
            timeout=30, look_for_keys=False, allow_agent=False,
        )

        shell = conn.invoke_shell(width=512, height=9999)
        shell.settimeout(60)
        time.sleep(2)
        shell.recv(65535)   # banner / prompt temizle

        parts: list[str] = []
        for cmd in cmds:
            shell.send(cmd + "\n")
            time.sleep(3)
            output_parts: list[str] = []
            deadline = time.time() + 60
            while time.time() < deadline:
                if shell.recv_ready():
                    chunk = shell.recv(65535).decode(errors="replace")
                    output_parts.append(chunk)
                    time.sleep(0.5)
                else:
                    time.sleep(1)
                    if not shell.recv_ready():
                        break
            out = "".join(output_parts)
            parts.append(f"\n{'='*60}\nCOMMAND: {cmd}\n{'='*60}\n{out}\n")

        conn.close()

        ts   = datetime.now().strftime("%H-%M-%S")
        path = daily_path / f"{ts}_{name}_{ip}.txt"
        path.write_text("".join(parts), encoding="utf-8")
        print(f"  [OK] {name}  →  {path.name}")
        logger.info("%s — Paramiko backup başarılı", name)
        return BackupResult.SUCCESS

    except paramiko.AuthenticationException:
        print(f"  [AUTH HATA] {name} — kimlik doğrulama başarısız")
        logger.warning("%s — auth başarısız", name)
        return BackupResult.RETRY

    except Exception as exc:
        print(f"  [HATA] {name} — {exc}")
        logger.error("%s — Paramiko backup hatası: %s", name, exc)
        return BackupResult.RETRY


# ── SSH backup (Cisco/Huawei/vb.) ─────────────────────────

def _backup_ssh(
    device: dict, credentials: dict, commands_dict: dict, daily_path: Path
) -> BackupResult:
    name        = device["name"]
    ip          = device["ip"]
    device_type = device["device_type"]
    cred_id     = device.get("credential_id", "")

    if cred_id not in credentials:
        print(f"  [HATA] {name} — credential bulunamadı ({cred_id})")
        logger.error("%s — credential yok: %s", name, cred_id)
        return BackupResult.PERMANENT

    cred = credentials[cred_id]
    cmds: list[str] = commands_dict.get("backup", {}).get(device_type, [])

    if not cmds:
        print(f"  [HATA] {name} — {device_type} için komut tanımlı değil")
        logger.error("%s — komut yok: %s", name, device_type)
        return BackupResult.PERMANENT

    try:
        conn = ConnectHandler(
            device_type=device_type, host=ip,
            username=cred["username"], password=cred["password"],
        )
        parts: list[str] = []
        for cmd in cmds:
            out = conn.send_command(cmd)
            parts.append(f"\n{'='*60}\nCOMMAND: {cmd}\n{'='*60}\n{out}\n")
        conn.disconnect()

        ts   = datetime.now().strftime("%H-%M-%S")
        path = daily_path / f"{ts}_{name}_{ip}.txt"
        path.write_text("".join(parts), encoding="utf-8")
        print(f"  [OK] {name}  →  {path.name}")
        logger.info("%s — SSH backup başarılı", name)
        return BackupResult.SUCCESS

    except NetmikoAuthenticationException:
        print(f"  [AUTH HATA] {name} — kimlik doğrulama başarısız (yeniden denenecek)")
        logger.warning("%s — auth başarısız (RETRY)", name)
        return BackupResult.RETRY

    except NetmikoTimeoutException:
        print(f"  [TIMEOUT] {name}")
        logger.warning("%s — timeout", name)
        return BackupResult.RETRY

    except Exception as exc:
        print(f"  [HATA] {name} — {exc}")
        logger.error("%s — SSH hatası: %s", name, exc)
        return BackupResult.RETRY
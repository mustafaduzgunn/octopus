"""
app/web.py  — Octopus Web Arayüzü v2
─────────────────────────────────────
Çalıştırma:
    cd octopusV3
    python -m app.web          # varsayılan port 5000
    python -m app.web --port 8080

Rol tablosu:
    admin  → her şey (vault, users, tüm modüller)
    user   → vault hariç modüller (backup, scan, inventory collector)
"""

from __future__ import annotations

import hashlib, ipaddress, json, os, secrets, sys, threading
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import Flask, jsonify, redirect, render_template_string, request, send_file, session, url_for

# ── Proje kökü ─────────────────────────────────────────────
_BASE = Path(__file__).parent
sys.path.insert(0, str(_BASE.parent))

from app.modules.password_manager.service import VaultService
from app.modules.password_manager.settings import PasswordSettings
import app.modules.network_backup.service as backup_svc
import app.modules.dynamic_inventory_scan.service as scan_svc
import app.modules.network_map.service as nmap_svc

# ── Yollar ─────────────────────────────────────────────────
VAULT_PATH    = _BASE / "data" / "vault.dat"
USERS_PATH    = _BASE / "data" / "users.json"
INV_PATH      = _BASE / "data" / "inventory.json"
EXCLUDE_PATH  = _BASE / "data" / "exclude.json"
COMMANDS_PATH = _BASE / "data" / "commands.json"
BACKUP_DIR       = _BASE / "backups"
SSH_LOG_DIR      = _BASE / "ssh_logs"
SSH_LOG_DIR.mkdir(exist_ok=True)
DEV_DETAILS_PATH  = _BASE / "data" / "device_details.json"
DEV_STATUS_PATH   = _BASE / "data" / "device_status.json"

# ── Flask ──────────────────────────────────────────────────
app = Flask(__name__)


@app.route("/favicon.ico")
def favicon():
    from flask import send_from_directory
    return send_from_directory(str(_BASE), "favicon.ico", mimetype="image/x-icon")
app.secret_key = secrets.token_hex(32)

# WebSocket desteği (SSH terminal için)
try:
    from flask_sock import Sock as _Sock
    _sock = _Sock(app)
    _HAS_SOCK = True
except ImportError:
    _sock = None
    _HAS_SOCK = False

# ── Vault singleton ────────────────────────────────────────
_vault: VaultService | None = None
_vault_lock = threading.Lock()

def get_vault() -> VaultService | None:
    return _vault

def set_vault(v: VaultService | None) -> None:
    global _vault
    with _vault_lock:
        _vault = v

# ── Arka plan iş yöneticisi ───────────────────────────────
_jobs: dict[str, dict] = {}
_jobs_lock = threading.Lock()

def _new_job(jid: str) -> None:
    with _jobs_lock:
        _jobs[jid] = {"status": "running", "log": [], "result": None, "error": None}

def _job_log(jid: str, line: str) -> None:
    with _jobs_lock:
        if jid in _jobs:
            _jobs[jid]["log"].append(line)

def _job_done(jid: str, result=None) -> None:
    with _jobs_lock:
        if jid in _jobs:
            _jobs[jid].update({"status": "done", "result": result})

def _job_fail(jid: str, error: str) -> None:
    with _jobs_lock:
        if jid in _jobs:
            _jobs[jid].update({"status": "error", "error": error})

def get_job(jid: str) -> dict | None:
    with _jobs_lock:
        return dict(_jobs.get(jid, {}))

# ── Kullanıcı yönetimi ─────────────────────────────────────
def _load_users() -> dict:
    if not USERS_PATH.exists():
        return {}
    return json.loads(USERS_PATH.read_text(encoding="utf-8"))

def _save_users(u: dict) -> None:
    USERS_PATH.write_text(json.dumps(u, indent=2, ensure_ascii=False), encoding="utf-8")

def _hash_pw(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

def _check_user(username: str, password: str) -> str | None:
    if username == "admin":
        v = VaultService(str(VAULT_PATH))
        if v.authenticate(password):
            set_vault(v)
            return "admin"
        return None
    users = _load_users()
    if username in users and users[username]["password_hash"] == _hash_pw(password):
        return users[username].get("role", "user")
    return None

# ── Auth dekoratörleri ─────────────────────────────────────
def login_required(f):
    @wraps(f)
    def d(*a, **kw):
        if "username" not in session:
            return jsonify({"error": "Oturum gerekli"}), 401
        return f(*a, **kw)
    return d

def admin_required(f):
    @wraps(f)
    def d(*a, **kw):
        if "username" not in session:
            return jsonify({"error": "Oturum gerekli"}), 401
        if session.get("role") != "admin":
            return jsonify({"error": "Yönetici yetkisi gerekli"}), 403
        return f(*a, **kw)
    return d

# ── Veri yardımcıları ─────────────────────────────────────
def _load_inventory() -> list:
    return json.loads(INV_PATH.read_text(encoding="utf-8")) if INV_PATH.exists() else []

def _save_inventory(inv: list) -> None:
    INV_PATH.write_text(json.dumps(inv, indent=2, ensure_ascii=False), encoding="utf-8")

def _load_commands() -> dict:
    return json.loads(COMMANDS_PATH.read_text(encoding="utf-8")) if COMMANDS_PATH.exists() else {}

def _load_exclude() -> list:
    return json.loads(EXCLUDE_PATH.read_text(encoding="utf-8")) if EXCLUDE_PATH.exists() else []

def _save_exclude(e: list) -> None:
    EXCLUDE_PATH.write_text(json.dumps(e, indent=2, ensure_ascii=False), encoding="utf-8")

def _load_device_details() -> dict:
    if not DEV_DETAILS_PATH.exists():
        return {}
    return json.loads(DEV_DETAILS_PATH.read_text(encoding="utf-8"))

def _save_device_details(dd: dict) -> None:
    DEV_DETAILS_PATH.write_text(json.dumps(dd, indent=2, ensure_ascii=False), encoding="utf-8")

def _load_device_status() -> dict:
    """device_status.json yükler. {ip: {status, ping, remote, checked_at, attempts}}"""
    if not DEV_STATUS_PATH.exists():
        return {}
    try:
        return json.loads(DEV_STATUS_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_device_status(ds: dict) -> None:
    DEV_STATUS_PATH.write_text(json.dumps(ds, indent=2, ensure_ascii=False), encoding="utf-8")


_status_lock = threading.Lock()


def _check_device_status(device: dict, vault: "VaultService") -> dict:
    """
    Tek bir cihazı kontrol eder:
      - ICMP / TCP ping → alive?
      - Uzak bağlantı (SSH veya REST API) → remote_ok?

    Döndürür:
      { status: "green"|"orange"|"red",
        ping: bool, remote: bool,
        checked_at: str, error: str }
    """
    import socket as _socket
    import subprocess as _sub

    ip          = device.get("ip", "")
    device_type = device.get("device_type", "").lower()
    cred_id     = device.get("credential_id", "")
    port        = device.get("port", 22)
    result      = {"ping": False, "remote": False,
                   "status": "red", "error": "",
                   "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

    # ── Ping ──────────────────────────────────────────────
    # TCP ping (22, 80, 443, 8080, 8443) veya ICMP
    def _tcp_ok(p: int) -> bool:
        try:
            with _socket.create_connection((ip, p), timeout=1.5):
                return True
        except Exception:
            return False

    def _icmp_ok() -> bool:
        try:
            r = _sub.run(["ping", "-c", "1", "-W", "2", ip],
                         stdout=_sub.DEVNULL, stderr=_sub.DEVNULL, timeout=4)
            return r.returncode == 0
        except Exception:
            return False

    result["ping"] = any(_tcp_ok(p) for p in [22, 80, 443, 8080, 8443]) or _icmp_ok()

    if not result["ping"]:
        result["status"] = "red"
        return result

    # ── Uzak bağlantı ─────────────────────────────────────
    cred = vault.vault.get(cred_id, {}) if cred_id else {}

    try:
        # FortiGate / Fortinet REST
        if any(t in device_type for t in ("fortigate", "fortinet")):
            import requests as _req
            import urllib3 as _u3
            _u3.disable_warnings()
            s = _req.Session(); s.verify = False
            api_token = cred.get("api_token", "")
            if api_token:
                s.headers["Authorization"] = f"Bearer {api_token}"
                params = {"access_token": api_token}
            else:
                r = s.post(f"https://{ip}:{port}/logincheck",
                           data={"username": cred.get("username",""),
                                 "secretkey": cred.get("password","")},
                           timeout=8)
                r.raise_for_status()
                csrf = r.cookies.get("ccsrftoken","").strip('"')
                if csrf: s.headers["X-CSRFTOKEN"] = csrf
                params = {}
            resp = s.get(f"https://{ip}:{port}/api/v2/monitor/system/status",
                         params=params, timeout=10)
            s.close()
            result["remote"] = resp.ok

        # F5 BIG-IP iControl REST
        elif any(t in device_type for t in ("bigip","f5","big-ip","velos","f5os")):
            import requests as _req, base64 as _b64, json as _json
            import urllib3 as _u3; _u3.disable_warnings()
            s = _req.Session(); s.verify = False
            b64 = _b64.b64encode(f"{cred.get('username','')}:{cred.get('password','')}".encode()).decode()
            token = ""
            for prov in ["tmos","local"]:
                try:
                    r = s.post(f"https://{ip}:{port}/mgmt/shared/authn/login",
                               data=_json.dumps({"username":cred.get("username",""),
                                                 "password":cred.get("password",""),
                                                 "loginProviderName":prov}).encode(),
                               headers={"Content-Type":"application/json",
                                        "Authorization":f"Basic {b64}"},
                               timeout=8)
                    token = r.json().get("token",{}).get("token","")
                    if token: break
                except Exception:
                    pass
            if token:
                s.headers["X-F5-Auth-Token"] = token
            resp = s.get(f"https://{ip}:{port}/mgmt/tm/sys/version", timeout=10)
            s.close()
            result["remote"] = resp.ok

        # Fortinet SSH tipler (FAZ, FMG, FAC vb.) — paramiko
        elif any(t in device_type for t in ("fortianalyzer","fortimanager",
                                             "fortiauthenticator","fortisandbox",
                                             "forticlientems","fortiems")):
            import paramiko as _pm
            c = _pm.SSHClient()
            c.set_missing_host_key_policy(_pm.AutoAddPolicy())
            c.connect(ip, port=port if port != 443 else 22,
                      username=cred.get("username",""), password=cred.get("password",""),
                      timeout=8, look_for_keys=False, allow_agent=False)
            c.close()
            result["remote"] = True

        # SSH (Cisco, Huawei, Dell, HP vb.) — paramiko
        else:
            import paramiko as _pm
            c = _pm.SSHClient()
            c.set_missing_host_key_policy(_pm.AutoAddPolicy())
            c.connect(ip, port=22, username=cred.get("username",""),
                      password=cred.get("password",""), timeout=8,
                      look_for_keys=False, allow_agent=False)
            c.close()
            result["remote"] = True

    except Exception as exc:
        result["remote"] = False
        result["error"]  = str(exc)[:120]

    result["status"] = "green" if result["remote"] else "orange"
    return result


def _run_status_check_for(devices: list, vault=None) -> int:
    """
    Verilen cihaz listesi için durum kontrolü yapar.
    vault verilmezse get_vault() kullanılır.
    Güncellenen cihaz sayısını döndürür.
    """
    import logging as _log
    import time as _t
    from concurrent.futures import ThreadPoolExecutor, as_completed as _asc

    _slog = _log.getLogger(__name__)
    v = vault or get_vault()
    if not v:
        _slog.warning("Status check: vault açık değil, atlandı.")
        return 0
    if not devices:
        return 0

    MAX_ATTEMPTS = 3
    RETRY_SLEEP  = 10
    MAX_WORKERS  = 20

    ds      = _load_device_status()
    updated = 0

    def _check_with_retry(device: dict) -> tuple[str, dict]:
        ip   = device.get("ip", "")
        last = None
        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                last = _check_device_status(device, v)
                if last["status"] == "green":
                    last["attempts"] = attempt
                    return ip, last
                if attempt < MAX_ATTEMPTS:
                    _t.sleep(RETRY_SLEEP)
            except Exception as exc:
                last = {"status": "red", "ping": False, "remote": False,
                        "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "error": str(exc)[:120]}
                if attempt < MAX_ATTEMPTS:
                    _t.sleep(RETRY_SLEEP)
        if last:
            last["attempts"] = MAX_ATTEMPTS
        return ip, last or {"status": "red", "ping": False, "remote": False,
                            "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "attempts": MAX_ATTEMPTS, "error": "Sonuç alınamadı"}

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(_check_with_retry, d): d
                   for d in devices if d.get("ip")}
        for future in _asc(futures):
            try:
                ip, result = future.result()
                if ip:
                    with _status_lock:
                        ds[ip] = result
                    updated += 1
            except Exception as exc:
                dev = futures[future]
                _slog.exception("Status check hatası %s: %s", dev.get("name"), exc)

    _save_device_status(ds)
    _slog.info("Status check tamamlandı: %d/%d cihaz güncellendi", updated, len(devices))
    return updated


def _run_scheduled_status_check() -> None:
    """Her gece 03:00'da tüm inventory'i kontrol eder."""
    inv = _load_inventory()
    _run_status_check_for(inv)


def _merge_device_details(new_results: list) -> None:
    """Collector sonuçlarını device_details.json'a yaz (IP bazlı, timestamp ile)."""
    dd = _load_device_details()
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for r in new_results:
        ip = r.get("ip", "")
        if ip:
            dd[ip] = {**r, "last_collected": ts}
    _save_device_details(dd)

def _secret_field(name: str) -> bool:
    return any(w in name.lower() for w in ("token", "password", "secret", "key", "pass"))

def _list_backups() -> list[dict]:
    if not BACKUP_DIR.exists():
        return []
    result = []
    for day_dir in sorted(BACKUP_DIR.iterdir(), reverse=True)[:30]:
        if not day_dir.is_dir():
            continue
        files = [{"name": f.name, "size": f.stat().st_size, "date": day_dir.name}
                 for f in sorted(day_dir.iterdir(), reverse=True) if f.is_file()]
        if files:
            result.append({"date": day_dir.name, "files": files, "count": len(files)})
    return result


def _resolve_backup_file(date: str, name: str):
    """date + name'den güvenli dosya yolu üretir. None döndürürse geçersiz."""
    import re
    # Sadece tarih formatına izin ver (YYYY-MM-DD veya HH-MM-SS_... şeklindekiler)
    if not date or not name:
        return None
    # Path traversal koruması
    if ".." in date or ".." in name or "/" in name or chr(92) in name:
        return None
    f = (BACKUP_DIR / date / name).resolve()
    if not str(f).startswith(str(BACKUP_DIR.resolve())):
        return None
    return f

def _parse_targets(raw: str) -> list[str]:
    raw = raw.strip()
    if "/" in raw:
        net = ipaddress.ip_network(raw, strict=False)
        return [str(ip) for ip in net.hosts()]
    if "-" in raw and raw.count(".") >= 3:
        s, e = raw.split("-", 1)
        start, end = ipaddress.ip_address(s.strip()), ipaddress.ip_address(e.strip())
        result, cur = [], start
        while cur <= end:
            result.append(str(cur)); cur += 1
        return result
    if "-" in raw:
        base, end_oct = raw.rsplit("-", 1)
        start = ipaddress.ip_address(base.strip())
        prefix = ".".join(str(start).split(".")[:3])
        s_oct = int(str(start).split(".")[-1])
        return [f"{prefix}.{i}" for i in range(s_oct, int(end_oct.strip()) + 1)]
    return [str(ipaddress.ip_address(raw))]

# ══════════════════════════════════════════════════════════
# Sayfa rotaları
# ══════════════════════════════════════════════════════════

@app.route("/")
def index():
    if "username" in session:
        return redirect(url_for("dashboard"))
    return render_template_string(TEMPLATE)

@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("index"))
    return render_template_string(TEMPLATE)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

# ══════════════════════════════════════════════════════════
# API — Auth
# ══════════════════════════════════════════════════════════

@app.route("/api/login", methods=["POST"])
def api_login():
    d = request.get_json()
    u, p = d.get("username", "").strip(), d.get("password", "")
    if not u or not p:
        return jsonify({"error": "Kullanıcı adı ve şifre gerekli"}), 400
    role = _check_user(u, p)
    if role is None:
        return jsonify({"error": "Kullanıcı adı veya şifre hatalı"}), 401
    session.permanent = False
    session["username"] = u
    session["role"] = role
    return jsonify({"success": True, "role": role, "username": u})

@app.route("/api/me")
def api_me():
    if "username" not in session:
        return jsonify({"error": "Oturum yok"}), 401
    return jsonify({"username": session["username"], "role": session["role"]})

@app.route("/api/stats")
@login_required
def api_stats():
    inv = _load_inventory()
    excl = _load_exclude()
    backups = _list_backups()
    stats = {
        "inventory": len(inv),
        "exclude": len(excl),
        "backup_days": len(backups),
        "backup_files": sum(d["count"] for d in backups),
        "vault": 0, "users": 0,
    }
    if session.get("role") == "admin":
        v = get_vault()
        if v:
            stats["vault"] = len(v.vault)
        stats["users"] = len(_load_users()) + 1
    return jsonify(stats)

# ══════════════════════════════════════════════════════════
# API — Vault
# ══════════════════════════════════════════════════════════

@app.route("/api/vault/entries")
@login_required
@admin_required
def api_vault_list():
    v = get_vault()
    if not v:
        return jsonify({"error": "Vault açık değil"}), 500
    return jsonify({svc: {k: {"value": val, "secret": _secret_field(k)}
                          for k, val in fields.items()}
                    for svc, fields in v.vault.items()})

@app.route("/api/vault/entry/<service>")
@login_required
@admin_required
def api_vault_get(service):
    v = get_vault()
    if not v or service not in v.vault:
        return jsonify({"error": "Bulunamadı"}), 404
    return jsonify({k: {"value": val, "secret": _secret_field(k)}
                    for k, val in v.vault[service].items()})

@app.route("/api/vault/entry", methods=["POST"])
@login_required
@admin_required
def api_vault_add():
    v = get_vault()
    if not v:
        return jsonify({"error": "Vault açık değil"}), 500
    d = request.get_json()
    svc = d.get("service", "").strip()
    if not svc:
        return jsonify({"error": "Servis adı boş olamaz"}), 400
    v.add(svc, d.get("fields", {}))
    return jsonify({"success": True})

@app.route("/api/vault/entry/<service>", methods=["PUT"])
@login_required
@admin_required
def api_vault_update(service):
    v = get_vault()
    if not v or service not in v.vault:
        return jsonify({"error": "Bulunamadı"}), 404
    v.add(service, request.get_json().get("fields", {}))
    return jsonify({"success": True})

@app.route("/api/vault/entry/<service>", methods=["DELETE"])
@login_required
@admin_required
def api_vault_delete(service):
    v = get_vault()
    if not v or not v.delete(service):
        return jsonify({"error": "Bulunamadı"}), 404
    return jsonify({"success": True})

@app.route("/api/vault/reveal/<service>/<field>")
@login_required
@admin_required
def api_vault_reveal(service, field):
    v = get_vault()
    if not v:
        return jsonify({"error": "Vault açık değil"}), 500
    entry = v.vault.get(service, {})
    if field not in entry:
        return jsonify({"error": "Alan bulunamadı"}), 404
    return jsonify({"value": entry[field]})

@app.route("/api/generate-password", methods=["POST"])
@login_required
def api_gen_pw():
    d = request.get_json() or {}
    ps = PasswordSettings(str(_BASE / "data" / "settings.json"))
    for k in ("length", "use_special_characters", "include_uppercase", "include_lowercase",
              "include_digits", "exclude_characters", "custom_special_characters"):
        if k in d:
            ps.settings[k] = d[k]
    return jsonify({"password": ps.generate()})

# ══════════════════════════════════════════════════════════
# API — Kullanıcılar
# ══════════════════════════════════════════════════════════

@app.route("/api/users")
@login_required
@admin_required
def api_users_list():
    u = _load_users()
    return jsonify({name: {"role": d.get("role", "user")} for name, d in u.items()})

@app.route("/api/users", methods=["POST"])
@login_required
@admin_required
def api_users_add():
    d = request.get_json()
    username = d.get("username", "").strip()
    password = d.get("password", "")
    role = d.get("role", "user")
    if not username or not password:
        return jsonify({"error": "Kullanıcı adı ve şifre gerekli"}), 400
    if len(password) < 6:
        return jsonify({"error": "Şifre en az 6 karakter olmalı"}), 400
    if username == "admin":
        return jsonify({"error": "'admin' rezerve edilmiştir"}), 400
    users = _load_users()
    if username in users:
        return jsonify({"error": "Kullanıcı zaten mevcut"}), 409
    users[username] = {"password_hash": _hash_pw(password), "role": role}
    _save_users(users)
    return jsonify({"success": True})

@app.route("/api/users/<username>", methods=["DELETE"])
@login_required
@admin_required
def api_users_delete(username):
    if username == "admin":
        return jsonify({"error": "Admin silinemez"}), 400
    users = _load_users()
    if username not in users:
        return jsonify({"error": "Bulunamadı"}), 404
    del users[username]
    _save_users(users)
    return jsonify({"success": True})

@app.route("/api/users/<username>/password", methods=["PUT"])
@login_required
@admin_required
def api_users_chpw(username):
    if username == "admin":
        return jsonify({"error": "Admin şifresi vault key'i ile aynıdır"}), 400
    pw = request.get_json().get("password", "")
    if not pw:
        return jsonify({"error": "Şifre boş olamaz"}), 400
    users = _load_users()
    if username not in users:
        return jsonify({"error": "Bulunamadı"}), 404
    users[username]["password_hash"] = _hash_pw(pw)
    _save_users(users)
    return jsonify({"success": True})

# ══════════════════════════════════════════════════════════
# API — Inventory
# ══════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════
# NETWORK MAP API
# ══════════════════════════════════════════════════

_nmap_job: dict = {}   # {id, status, progress, message, links}
_nmap_lock = __import__("threading").Lock()


@app.route("/api/device-status/run-single/<path:ip>", methods=["POST"])
@login_required
def api_device_status_run_single(ip: str):
    """Tek bir cihaz için durum kontrolü tetikler."""
    import threading as _thr
    inv     = _load_inventory()
    devices = [d for d in inv if d.get("ip") == ip]
    if not devices:
        return jsonify({"error": "Cihaz bulunamadı"}), 404
    t = _thr.Thread(target=_run_status_check_for, args=(devices,), daemon=True)
    t.start()
    return jsonify({"success": True, "message": f"{ip} için durum kontrolü başlatıldı"})


@app.route("/api/netmap/build", methods=["POST"])
@login_required
@admin_required
def api_netmap_build():
    """Arka planda topoloji oluşturma işini başlatır."""
    import threading as _thr
    import uuid as _uuid

    v = get_vault()
    if not v:
        return jsonify({"error": "Vault açık değil"}), 400

    job_id = _uuid.uuid4().hex[:8]

    def _run():
        global _nmap_job
        with _nmap_lock:
            _nmap_job = {"id": job_id, "status": "running",
                         "progress": 0, "message": "Başlatılıyor…", "links": []}

        def _cb(msg, pct):
            with _nmap_lock:
                _nmap_job["message"]  = msg
                _nmap_job["progress"] = max(0, min(100, int(pct))) if pct >= 0 else _nmap_job["progress"]

        try:
            builder = nmap_svc.TopologyBuilder(v, progress_cb=_cb)
            links   = builder.build()
            nmap_svc.save_map(links)
            with _nmap_lock:
                _nmap_job["status"]   = "done"
                _nmap_job["progress"] = 100
                _nmap_job["message"]  = f"Tamamlandı — {len(links)} bağlantı"
                _nmap_job["links"]    = links
        except Exception as exc:
            import traceback as _tb
            with _nmap_lock:
                _nmap_job["status"]  = "error"
                _nmap_job["message"] = str(exc)

    t = _thr.Thread(target=_run, daemon=True)
    t.start()
    return jsonify({"job_id": job_id})


@app.route("/api/netmap/status", methods=["GET"])
@login_required
def api_netmap_status():
    """Topoloji oluşturma işinin durumunu döndürür."""
    with _nmap_lock:
        job = dict(_nmap_job)
    job.pop("links", None)   # büyük veriyi buradan döndürme
    return jsonify(job)


@app.route("/api/netmap/links", methods=["GET"])
@login_required
def api_netmap_links():
    """Kaydedilmiş topoloji bağlantılarını döndürür."""
    links = nmap_svc.load_map()
    return jsonify(links)


@app.route("/api/netmap/drawio", methods=["GET"])
@login_required
def api_netmap_drawio():
    """Draw.io XML olarak topoloji dışa aktarır."""
    links = nmap_svc.load_map()
    if not links:
        return jsonify({"error": "Topoloji verisi yok, önce oluşturun"}), 404
    xml = nmap_svc.generate_drawio(links)
    from flask import Response
    return Response(
        xml,
        mimetype="application/xml",
        headers={"Content-Disposition": "attachment; filename=network_map.drawio"}
    )


@app.route("/api/inventory/rename-hostname", methods=["POST"])
@login_required
@admin_required
def api_inv_rename_hostname():
    """Kullanıcı onaylı toplu hostname → kayıt adı güncellemesi."""
    items = request.get_json()  # [{inv_name, hostname}, ...]
    if not isinstance(items, list):
        return jsonify({"error": "Liste bekleniyor"}), 400
    inv = _load_inventory()
    updated = 0
    for item in items:
        inv_name = (item.get("inv_name") or "").strip().upper()
        hostname  = (item.get("hostname")  or "").strip().upper()
        if not inv_name or not hostname:
            continue
        for dev in inv:
            if dev.get("name", "").upper() == inv_name:
                dev["name"] = hostname
                updated += 1
                break
    if updated:
        _save_inventory(inv)
    return jsonify({"success": True, "updated": updated})


@app.route("/api/device-status", methods=["GET"])
@login_required
def api_device_status():
    """Tüm cihazların son durum bilgisini döndürür."""
    return jsonify(_load_device_status())


@app.route("/api/device-status/run", methods=["POST"])
@login_required
@admin_required
def api_device_status_run():
    """
    Manuel status check tetikler (arka planda).

    Body (opsiyonel, JSON):
      {}                          → tüm inventory
      {"ips": ["1.2.3.4", ...]}   → sadece bu IP'ler
      {"filter": {                → filtre ile eşleşenler
        "type": "cisco_ios",
        "cred": "sw",
        "tag":  "golbasi",
        "name": "CORE"            (içerir, büyük/küçük harf yok)
      }}
    """
    import threading as _thr

    body    = request.get_json(silent=True) or {}
    inv     = _load_inventory()
    devices = inv   # varsayılan: tümü

    # IP listesi verilmişse
    if body.get("ips"):
        ip_set  = set(body["ips"])
        devices = [d for d in inv if d.get("ip") in ip_set]

    # Filtre verilmişse
    elif body.get("filter"):
        f       = body["filter"]
        devices = []
        for d in inv:
            if f.get("type") and d.get("device_type","") != f["type"]:
                continue
            if f.get("cred") and d.get("credential_id","") != f["cred"]:
                continue
            if f.get("tag") and f["tag"] not in d.get("tags", []):
                continue
            if f.get("name") and f["name"].lower() not in d.get("name","").lower():
                continue
            devices.append(d)

    if not devices:
        return jsonify({"success": False, "message": "Eşleşen cihaz bulunamadı"}), 404

    t = _thr.Thread(
        target=_run_status_check_for,
        args=(devices,),
        daemon=True
    )
    t.start()
    return jsonify({
        "success": True,
        "message": f"{len(devices)} cihaz için durum kontrolü başlatıldı"
    })


@app.route("/api/inventory")
@login_required
def api_inv_list():
    inv = _load_inventory()
    # additional_ips string→list normalize
    for d in inv:
        ai = d.get("additional_ips")
        if isinstance(ai, str):
            d["additional_ips"] = [x.strip() for x in ai.replace(";",",").split(",") if x.strip()]
        elif ai is None:
            d["additional_ips"] = []
    return jsonify(inv)

@app.route("/api/inventory", methods=["POST"])
@login_required
@admin_required
def api_inv_add():
    d = request.get_json()
    if not d.get("name") or not d.get("ip"):
        return jsonify({"error": "Ad ve IP gerekli"}), 400
    try:
        ipaddress.ip_address(d["ip"].strip())
    except ValueError:
        return jsonify({"error": "Geçersiz IP adresi"}), 400
    inv = _load_inventory()
    # IP duplicate
    if any(x.get("ip") == d["ip"].strip() for x in inv):
        return jsonify({"error": "Bu IP zaten kayıtlı"}), 409
    # MAC duplicate
    from app.modules.dynamic_inventory_scan.service import _normalize_mac, _inventory_by_mac
    mac_norm = _normalize_mac(d.get("mac_address", ""))
    if mac_norm and mac_norm in _inventory_by_mac(inv):
        return jsonify({"error": "Bu MAC adresi zaten kayıtlı"}), 409
    # Serial duplicate
    sn = (d.get("serial_no") or "").strip().upper()
    if sn and any((x.get("serial_no") or "").strip().upper() == sn for x in inv):
        return jsonify({"error": "Bu serial numara zaten kayıtlı"}), 409
    # Normalize mac/serial
    if d.get("mac_address"):
        from app.modules.dynamic_inventory_scan.service import _normalize_mac
        d["mac_address"] = _normalize_mac(d["mac_address"]) or d["mac_address"]
    if d.get("serial_no"):
        d["serial_no"] = d["serial_no"].strip().upper()
    inv.append(d)
    _save_inventory(inv)
    return jsonify({"success": True})

@app.route("/api/inventory/<int:idx>", methods=["PUT"])
@login_required
@admin_required
def api_inv_update(idx):
    inv = _load_inventory()
    if idx < 0 or idx >= len(inv):
        return jsonify({"error": "Geçersiz indeks"}), 404
    updated = request.get_json()
    # Mevcut kayıttaki bazı alanları koru (scan tarafından doldurulanlar)
    existing = inv[idx]
    for preserve_key in ("mac_address", "serial_no", "additional_ips",
                         "discovered_at", "ip_updated_at", "last_seen_hostname"):
        if preserve_key in existing and preserve_key not in updated:
            updated[preserve_key] = existing[preserve_key]
    # MAC/serial normalize
    if updated.get("mac_address"):
        from app.modules.dynamic_inventory_scan.service import _normalize_mac
        updated["mac_address"] = _normalize_mac(updated["mac_address"]) or updated["mac_address"]
    if updated.get("serial_no"):
        updated["serial_no"] = updated["serial_no"].strip().upper()
    inv[idx] = updated
    _save_inventory(inv)
    return jsonify({"success": True})

@app.route("/api/inventory/<int:idx>", methods=["DELETE"])
@login_required
@admin_required
def api_inv_delete(idx):
    inv = _load_inventory()
    if idx < 0 or idx >= len(inv):
        return jsonify({"error": "Geçersiz indeks"}), 404
    inv.pop(idx)
    _save_inventory(inv)
    return jsonify({"success": True})

@app.route("/api/inventory/<int:idx>/additional-ips", methods=["POST"])
@login_required
@admin_required
def api_inv_add_ip(idx):
    inv = _load_inventory()
    if idx < 0 or idx >= len(inv):
        return jsonify({"error": "Geçersiz indeks"}), 404
    try:
        new_ip = str(ipaddress.ip_address(request.get_json().get("ip", "").strip()))
    except ValueError:
        return jsonify({"error": "Geçersiz IP"}), 400
    all_ips = scan_svc._inventory_ips(inv)
    if new_ip in all_ips:
        return jsonify({"error": f"{new_ip} zaten kayıtlı"}), 409
    inv[idx].setdefault("additional_ips", []).append(new_ip)
    _save_inventory(inv)
    return jsonify({"success": True})

@app.route("/api/inventory/<int:idx>/additional-ips/<ip>", methods=["DELETE"])
@login_required
@admin_required
def api_inv_del_ip(idx, ip):
    inv = _load_inventory()
    if idx < 0 or idx >= len(inv):
        return jsonify({"error": "Geçersiz indeks"}), 404
    extras = inv[idx].get("additional_ips", [])
    if ip not in extras:
        return jsonify({"error": "IP bulunamadı"}), 404
    extras.remove(ip)
    inv[idx]["additional_ips"] = extras
    _save_inventory(inv)
    return jsonify({"success": True})

# ══════════════════════════════════════════════════════════
# API — Cihaz Detay  (inventory + collector + backup birleşimi)
# ══════════════════════════════════════════════════════════

def _get_device_collector_data(device_ip: str, device_name: str) -> dict | None:
    """Collector çıktılarından ve device_details.json'dan bu cihaza ait veriyi döner."""
    # Önce device_details.json'a bak (en güncel, neighbors/portchannels içerir)
    dd = _load_device_details()
    if device_ip in dd:
        entry = dict(dd[device_ip])
        return entry

    # Yoksa collector output dosyalarından ara
    output_dir = _BASE / "modules" / "inventory_collector" / "outputs"
    if not output_dir.exists():
        return None
    for f in sorted(output_dir.glob("*.json"), reverse=True):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            for item in data.get("successful", []):
                if item.get("ip") == device_ip or item.get("device") == device_name:
                    # Merge with device_details if exists for neighbors
                    result = {"source_file": f.name, "collected_at": f.stem, **item}
                    return result
        except Exception:
            continue
    return None

def _get_device_backups(device_ip: str, device_name: str, additional_ips=None) -> list[dict]:
    """Bu cihaza ait tüm backup dosyalarını döner (kesin IP eşleşmesi)."""
    import re as _re
    if not BACKUP_DIR.exists():
        return []
    def _ip_match(ip: str, fname: str) -> bool:
        # IP'den sonra rakam veya nokta gelmemeli (10.1.1.3 vs 10.1.1.34 ayrımı)
        return bool(_re.search(_re.escape(ip) + r'(?:[^0-9.]|$)', fname))
    search_ips = [device_ip]
    if additional_ips:
        if isinstance(additional_ips, str):
            search_ips += [x.strip() for x in additional_ips.replace(";", ",").split(",") if x.strip()]
        elif isinstance(additional_ips, list):
            search_ips += [str(x).strip() for x in additional_ips if x]
    name_lower = device_name.lower()
    results = []
    for day_dir in sorted(BACKUP_DIR.iterdir(), reverse=True):
        if not day_dir.is_dir():
            continue
        for f in sorted(day_dir.iterdir(), reverse=True):
            if not f.is_file():
                continue
            fname = f.name
            if any(_ip_match(ip, fname) for ip in search_ips) or name_lower in fname.lower():
                results.append({
                    "date": day_dir.name,
                    "name": fname,
                    "size": f.stat().st_size,
                })
    return results

@app.route("/api/device/<int:idx>/detail")
@login_required
def api_device_detail(idx):
    """Cihaz detay sayfası için tüm verileri tek endpoint'te toplar."""
    inv = _load_inventory()
    if idx < 0 or idx >= len(inv):
        return jsonify({"error": "Cihaz bulunamadı"}), 404
    device = inv[idx]
    ip   = device.get("ip", "")
    name = device.get("name", "")

    collector_data = _get_device_collector_data(ip, name)
    backups        = _get_device_backups(ip, name)

    return jsonify({
        "device":    device,
        "idx":       idx,
        "collector": collector_data,
        "backups":   backups,
    })

@app.route("/api/device-details", methods=["GET"])
@login_required
def api_device_details_all():
    """Tüm device_details.json içeriğini döndürür (model haritası için)."""
    return jsonify(_load_device_details())


@app.route("/api/device/<int:idx>/collect", methods=["POST"])
@login_required
def api_device_collect(idx):
    """Tek bir cihaz için collector'ı çalıştırır."""
    v = get_vault()
    if not v:
        return jsonify({"error": "Vault açık değil"}), 500
    inv = _load_inventory()
    if idx < 0 or idx >= len(inv):
        return jsonify({"error": "Cihaz bulunamadı"}), 404
    device = inv[idx]

    job_id = secrets.token_hex(8)
    _new_job(job_id)

    def run():
        import app.modules.inventory_collector.module as col_mod
        cred_id = device.get("credential_id", "")
        if not cred_id or cred_id not in v.vault:
            _job_fail(job_id, f"Credential bulunamadı: '{cred_id}'")
            return
        try:
            _job_log(job_id, f"{device['name']} ({device['ip']}) envanter toplanıyor…")
            res = col_mod._collect_single(device, v.vault[cred_id])
            if res.get("success"):
                # Kaydet
                output_dir = _BASE / "modules" / "inventory_collector" / "outputs"
                output_dir.mkdir(parents=True, exist_ok=True)
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                out_file = output_dir / f"inventory_result_{ts}.json"
                out_file.write_text(
                    json.dumps({"successful": [res["data"]], "failed": [], "skipped": []},
                               indent=4, ensure_ascii=False), encoding="utf-8")
                data = res["data"]
                for k, val in data.items():
                    if k not in ("device", "ip"):
                        _job_log(job_id, f"  {k}: {val}")
                _job_log(job_id, "✅ Envanter başarıyla alındı.")
                _merge_device_details([res["data"]])
                _job_done(job_id, res["data"])
            else:
                _job_fail(job_id, res.get("error", "Bilinmeyen hata"))
        except Exception as e:
            _job_fail(job_id, str(e))

    threading.Thread(target=run, daemon=True).start()
    return jsonify({"job_id": job_id})

@app.route("/api/device/<int:idx>/backup", methods=["POST"])
@login_required
def api_device_backup(idx):
    """Tek bir cihaz için backup alır."""
    v = get_vault()
    if not v:
        return jsonify({"error": "Vault açık değil"}), 500
    inv = _load_inventory()
    if idx < 0 or idx >= len(inv):
        return jsonify({"error": "Cihaz bulunamadı"}), 404
    device = inv[idx]

    job_id = secrets.token_hex(8)
    _new_job(job_id)

    def run():
        class Cap:
            def write(self, s):
                s = s.strip()
                if s: _job_log(job_id, s)
            def flush(self): pass
        import sys as _sys
        old = _sys.stdout; _sys.stdout = Cap()
        try:
            cmds = _load_commands()
            backup_svc.perform_backup([device], v.vault, cmds)
            _job_done(job_id)
        except Exception as e:
            _job_fail(job_id, str(e))
        finally:
            _sys.stdout = old

    threading.Thread(target=run, daemon=True).start()
    return jsonify({"job_id": job_id})

# ══════════════════════════════════════════════════════════
# API — Exclude
# ══════════════════════════════════════════════════════════

@app.route("/api/exclude")
@login_required
def api_excl_list():
    return jsonify(_load_exclude())

@app.route("/api/exclude", methods=["POST"])
@login_required
@admin_required
def api_excl_add():
    d = request.get_json()
    try:
        ip = str(ipaddress.ip_address(d.get("ip", "").strip()))
    except ValueError:
        return jsonify({"error": "Geçersiz IP"}), 400
    entries = _load_exclude()
    if any(e["ip"] == ip for e in entries):
        return jsonify({"error": "IP zaten listede"}), 409
    entries.append({"ip": ip, "description": d.get("description", ""),
                    "added_at": datetime.now().strftime("%Y-%m-%d %H:%M")})
    _save_exclude(entries)
    return jsonify({"success": True})

@app.route("/api/exclude/<int:idx>", methods=["DELETE"])
@login_required
@admin_required
def api_excl_delete(idx):
    entries = _load_exclude()
    if idx < 0 or idx >= len(entries):
        return jsonify({"error": "Geçersiz indeks"}), 404
    entries.pop(idx)
    _save_exclude(entries)
    return jsonify({"success": True})

# ══════════════════════════════════════════════════════════
# API — Job (arka plan iş durumu)
# ══════════════════════════════════════════════════════════

@app.route("/api/job/<job_id>")
@login_required
def api_job_status(job_id):
    j = get_job(job_id)
    if not j:
        return jsonify({"error": "İş bulunamadı"}), 404
    return jsonify(j)

# ══════════════════════════════════════════════════════════
# API — Network Backup
# ══════════════════════════════════════════════════════════

@app.route("/api/backup/list")
@login_required
def api_backup_list():
    return jsonify(_list_backups())

@app.route("/api/backup/start", methods=["POST"])
@login_required
def api_backup_start():
    v = get_vault()
    if not v:
        return jsonify({"error": "Vault açık değil"}), 500
    d = request.get_json() or {}
    mode = d.get("mode", "full")
    tag  = d.get("tag", "").strip()

    inv = _load_inventory()
    if mode == "tag":
        if not tag:
            return jsonify({"error": "Tag boş olamaz"}), 400
        devices = [x for x in inv if tag in x.get("tags", [])]
        if not devices:
            return jsonify({"error": f"'{tag}' etiketli cihaz bulunamadı"}), 404
    else:
        devices = inv

    job_id = secrets.token_hex(8)
    _new_job(job_id)

    def run():
        class Cap:
            def write(self, s):
                s = s.strip()
                if s: _job_log(job_id, s)
            def flush(self): pass

        import sys as _sys
        old = _sys.stdout; _sys.stdout = Cap()
        try:
            cmds = _load_commands()
            backup_svc.perform_backup(devices, v.vault, cmds)
            _job_done(job_id)
        except Exception as e:
            _job_fail(job_id, str(e))
        finally:
            _sys.stdout = old

    threading.Thread(target=run, daemon=True).start()
    return jsonify({"job_id": job_id, "device_count": len(devices)})

# ══════════════════════════════════════════════════════════
# API — Dynamic Inventory Scan
# ══════════════════════════════════════════════════════════

@app.route("/api/scan/start", methods=["POST"])
@login_required
def api_scan_start():
    v = get_vault()
    if not v:
        return jsonify({"error": "Vault açık değil"}), 500
    d = request.get_json() or {}
    targets_raw = d.get("targets", "").strip()
    if not targets_raw:
        return jsonify({"error": "Hedef IP/blok gerekli"}), 400
    try:
        targets = _parse_targets(targets_raw)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    if len(targets) > 1024:
        return jsonify({"error": "En fazla 1024 IP taranabilir"}), 400

    job_id = secrets.token_hex(8)
    _new_job(job_id)

    def run():
        inv = _load_inventory()
        results = []

        def on_result(ip, res):
            if res.alive and not res.in_inventory:
                line = f"[{ip}] mac={res.mac} vendor={res.vendor} ports={res.open_ports}"
                if res.ssh_success:
                    inv_status = '✅ eklendi' if res.added_to_inv else ('🔄 IP güncellendi' if res.ip_updated else '⚠️ atlandı')
                    line += f" SSH✅ type={res.device_type} serial={res.serial_no or '-'} inv={inv_status}"
                _job_log(job_id, line)
            results.append(res)

        try:
            scan_svc.scan_range(targets, inv, v.vault, progress_cb=on_result)
            alive = [r for r in results if r.alive and not r.in_inventory]
            added = [r for r in alive if r.added_to_inv]
            ssh_ok = [r for r in alive if r.ssh_success]
            _job_log(job_id, "─── TARAMA ÖZETİ ───")
            _job_log(job_id, f"Taranan: {len(targets)}  Aktif(yeni): {len(alive)}  SSH✅: {len(ssh_ok)}  Eklendi: {len(added)}")
            _job_done(job_id, {
                "total": len(targets), "alive": len(alive),
                "ssh_ok": len(ssh_ok), "added": len(added),
                "devices": [{"ip": r.ip, "mac": r.mac, "vendor": r.vendor,
                              "ports": r.open_ports, "ssh": r.ssh_success,
                              "type": r.device_type, "added": r.added_to_inv,
                              "name": r.inv_name}
                             for r in results if r.alive and not r.in_inventory]
            })
        except Exception as e:
            _job_fail(job_id, str(e))

    threading.Thread(target=run, daemon=True).start()
    return jsonify({"job_id": job_id, "target_count": len(targets)})

# ══════════════════════════════════════════════════════════
# API — Inventory Collector
# ══════════════════════════════════════════════════════════

@app.route("/api/collector/start", methods=["POST"])
@login_required
def api_collector_start():
    v = get_vault()
    if not v:
        return jsonify({"error": "Vault açık değil"}), 500
    d = request.get_json() or {}
    tag = d.get("tag", "all").strip()

    inv = _load_inventory()
    devices = inv if tag.lower() == "all" else [x for x in inv if tag in x.get("tags", [])]
    if not devices:
        return jsonify({"error": f"'{tag}' etiketli cihaz bulunamadı"}), 404

    job_id = secrets.token_hex(8)
    _new_job(job_id)

    def run():
        from concurrent.futures import ThreadPoolExecutor, as_completed
        import app.modules.inventory_collector.module as col_mod

        results, failed, skipped = [], [], []
        total = len(devices)
        _job_log(job_id, f"{total} cihaz işlenecek…")

        def collect_one(device):
            cred_id = device.get("credential_id", "")
            if not cred_id or cred_id not in v.vault:
                return None, device, f"credential bulunamadı: {cred_id}"
            try:
                res = col_mod._collect_single(device, v.vault[cred_id])
                return res, device, None
            except Exception as e:
                return None, device, str(e)

        with ThreadPoolExecutor(max_workers=5) as pool:
            futures = {pool.submit(collect_one, dev): dev for dev in devices}
            for fut in as_completed(futures):
                res, device, err = fut.result()
                if err and res is None:
                    _job_log(job_id, f"[ATLA] {device['name']} — {err}")
                    skipped.append({"device": device["name"], "error": err})
                elif res and res.get("success"):
                    data = res["data"]
                    ch   = data.get("collected_hostname", "")
                    dn   = device.get("name", "")
                    if ch and ch.upper() != dn.upper():
                        data["_hostname_diff"] = {"inv_name": dn, "hostname": ch.upper()}
                        _job_log(job_id, f"[✅] {dn} — envanter alındı ⚠️ hostname farklı: {dn} → {ch.upper()}")
                    else:
                        _job_log(job_id, f"[✅] {dn} — envanter alındı")
                    results.append(data)
                else:
                    em = (res or {}).get("error", err or "bilinmeyen")
                    _job_log(job_id, f"[❌] {device['name']} — {em}")
                    failed.append({"device": device["name"], "ip": device.get("ip",""), "error": em})

        output_dir = _BASE / "modules" / "inventory_collector" / "outputs"
        output_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_file = output_dir / f"inventory_result_{ts}.json"
        out_file.write_text(
            json.dumps({"successful": results, "failed": failed, "skipped": skipped},
                       indent=4, ensure_ascii=False), encoding="utf-8")
        # device_details.json'u güncelle
        _merge_device_details(results)
        _job_log(job_id, "─── ÖZET ───")
        _job_log(job_id, f"Başarılı: {len(results)}/{total}  Başarısız: {len(failed)}  Atlandı: {len(skipped)}")
        hostname_diffs = [r["_hostname_diff"] for r in results if r.get("_hostname_diff")]
        _job_done(job_id, {"results": results, "failed": failed,
                            "skipped": skipped, "hostname_diffs": hostname_diffs})

    threading.Thread(target=run, daemon=True).start()
    return jsonify({"job_id": job_id, "device_count": len(devices)})

@app.route("/api/collector/outputs")
@login_required
def api_collector_outputs():
    output_dir = _BASE / "modules" / "inventory_collector" / "outputs"
    if not output_dir.exists():
        return jsonify([])
    files = []
    for f in sorted(output_dir.iterdir(), reverse=True)[:20]:
        if f.suffix == ".json":
            files.append({"name": f.name, "size": f.stat().st_size,
                           "mtime": datetime.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M")})
    return jsonify(files)

@app.route("/api/collector/output/<filename>")
@login_required
def api_collector_output(filename):
    output_dir = _BASE / "modules" / "inventory_collector" / "outputs"
    f = output_dir / filename
    if not f.exists() or f.suffix != ".json":
        return jsonify({"error": "Bulunamadı"}), 404
    return jsonify(json.loads(f.read_text(encoding="utf-8")))


# ══════════════════════════════════════════════════════════
# API — Backup dosyası okuma + diff
# ══════════════════════════════════════════════════════════

@app.route("/api/backup/file")
@login_required
def api_backup_file():
    """Backup dosyasının içeriğini döner.
    Parametreler: ?date=2026-03-14&name=xxx.conf
    Eski uyumluluk için ?path= da kabul edilir (sadece dosya adı).
    """
    date = request.args.get("date", "")
    name = request.args.get("name", "")

    # Eski ?path= desteği: path içinden sadece date/name çıkar
    if not name:
        raw_path = request.args.get("path", "")
        if raw_path:
            import pathlib as _pl2
            p = _pl2.PurePosixPath(raw_path.replace(chr(92)+chr(92), "/").replace(chr(92), "/"))
            name = p.name
            if len(p.parts) >= 2:
                date = p.parts[-2]

    if not name:
        return jsonify({"error": "name gerekli"}), 400

    f = _resolve_backup_file(date, name)
    if f is None:
        return jsonify({"error": "Geçersiz dosya yolu"}), 400
    if not f.exists() or not f.is_file():
        # date yoksa tüm backup klasörünü tara
        if not date:
            for day_dir in BACKUP_DIR.iterdir():
                candidate = (day_dir / name).resolve()
                if candidate.exists() and str(candidate).startswith(str(BACKUP_DIR.resolve())):
                    f = candidate
                    break
        if not f or not f.exists():
            return jsonify({"error": "Dosya bulunamadı"}), 404
    if f.suffix not in (".txt", ".conf", ".log", ".cfg", ".bak"):
        return jsonify({"error": "Bu dosya tipi görüntülenemez"}), 400
    try:
        text = f.read_text(encoding="utf-8", errors="replace")
        return jsonify({"content": text, "name": f.name})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/backup/diff")
@login_required
def api_backup_diff():
    """İki backup dosyası arasında satır bazlı diff döner.
    Parametreler: ?a=DATE:NAME&b=DATE:NAME  (iki nokta üst üste ayraç)
    """
    import difflib

    def _parse_ref(ref: str):
        """date:name veya eski tam path → Path nesnesi"""
        if not ref:
            return None
        if ":" in ref and not ref.startswith("/") and not (len(ref) > 1 and ref[1] == ":"):
            # date:name formatı
            parts = ref.split(":", 1)
            return _resolve_backup_file(parts[0], parts[1])
        # Eski uyumluluk: path string — sadece BACKUP_DIR altındaki dosyalara izin ver
        import pathlib as _pl2
        p = _pl2.PurePosixPath(ref.replace(chr(92)+chr(92), "/").replace(chr(92), "/"))
        return _resolve_backup_file(p.parts[-2] if len(p.parts) >= 2 else "", p.name)

    p1 = request.args.get("a", "")
    p2 = request.args.get("b", "")
    if not p1 or not p2:
        return jsonify({"error": "a ve b gerekli"}), 400

    f1, f2 = _parse_ref(p1), _parse_ref(p2)
    if f1 is None or f2 is None:
        return jsonify({"error": "Geçersiz dosya referansı"}), 400
    if not f1.exists() or not f2.exists():
        return jsonify({"error": "Dosyalardan biri bulunamadı"}), 404

    t1 = f1.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
    t2 = f2.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
    diff = list(difflib.unified_diff(t1, t2, fromfile=f1.name, tofile=f2.name, lineterm=""))
    return jsonify({"diff": diff, "a": f1.name, "b": f2.name,
                    "changed": any(l.startswith(("+", "-")) and not l.startswith(("---","+++")) for l in diff)})

# ══════════════════════════════════════════════════════════
# API — Komşuluk / Neighbor (SSH ile CDP/LLDP + portchannel)
# ══════════════════════════════════════════════════════════

@app.route("/api/device-details/<path:ip>/neighbors", methods=["POST"])
@login_required
def api_device_neighbors(ip):
    """CDP/LLDP komşuları + port-channel + VLAN bilgisini toplar."""
    v = get_vault()
    if not v:
        return jsonify({"error": "Vault açık değil"}), 500
    inv = _load_inventory()
    device = next((d for d in inv if d.get("ip") == ip), None)
    if not device:
        return jsonify({"error": "Cihaz bulunamadı"}), 404
    cred_id = device.get("credential_id", "")
    if not cred_id or cred_id not in v.vault:
        return jsonify({"error": f"Credential bulunamadı: {cred_id}"}), 400

    job_id = secrets.token_hex(8)
    _new_job(job_id)

    def run():
        import re
        import time
        import paramiko as _paramiko
        from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException
        cred = v.vault[cred_id]
        dt = device.get("device_type", "").lower()
        _job_log(job_id, f"[{device['name']}] komşuluk bilgisi toplanıyor…")

        neighbors    = []
        portchannels = {}  # po_name → {members, vlans}

        def _norm_iface(s):
            s = s.strip()
            for long, short in [
                ("TwentyFiveGigE","Tw"),("HundredGigE","Hu"),("FortyGigabitEthernet","Fo"),
                ("TenGigabitEthernet","Te"),("GigabitEthernet","Gi"),
                ("FastEthernet","Fa"),("Ethernet","Et"),("Port-channel","Po"),("Management","Mg"),
            ]:
                if s.lower().startswith(long.lower()):
                    return short + s[len(long):]
            return s

        def _save_and_done():
            # Komşu + portchannel eşleştir
            for nb in neighbors:
                lp = nb.get("local_port", "")
                lp_norm = _norm_iface(lp)
                for po_name, po_data in portchannels.items():
                    members_norm = [_norm_iface(m2) for m2 in po_data["members"]]
                    if (lp in po_data["members"] or lp_norm in members_norm
                            or lp == po_name or lp_norm == _norm_iface(po_name)):
                        nb["portchannel"] = po_name
                        nb["portchannel_members"] = po_data["members"]
                        nb["vlans"] = sorted(set(v2 for v2 in po_data["vlans"] if v2.strip()))
                        break
            dd = _load_device_details()
            if ip not in dd:
                dd[ip] = {"ip": ip, "device": device.get("name", ip)}
            dd[ip]["neighbors"]            = neighbors
            dd[ip]["portchannels"]         = portchannels
            dd[ip]["neighbors_collected"]  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            _save_device_details(dd)
            _job_log(job_id, f"✅ {len(neighbors)} komşu bulundu, {len(portchannels)} port-channel")
            _job_done(job_id, {"neighbors": neighbors, "portchannels": portchannels})

        # ── Extreme Networks ExtremeXOS — Paramiko ────────────
        if "extreme" in dt:
            try:
                conn = _paramiko.SSHClient()
                conn.set_missing_host_key_policy(_paramiko.AutoAddPolicy())
                conn.connect(ip, port=22,
                             username=cred.get("username",""), password=cred.get("password",""),
                             timeout=30, look_for_keys=False, allow_agent=False)
                shell = conn.invoke_shell(width=512, height=9999)
                shell.settimeout(60)
                time.sleep(2)
                shell.recv(65535)   # banner temizle

                def _send(cmd, wait=2):
                    shell.send(cmd + "\n")
                    time.sleep(wait)
                    parts = []
                    deadline = time.time() + 30
                    while time.time() < deadline:
                        if shell.recv_ready():
                            parts.append(shell.recv(65535).decode(errors="replace"))
                            time.sleep(0.3)
                        else:
                            time.sleep(0.5)
                            if not shell.recv_ready():
                                break
                    return "".join(parts)

                lldp_out = _send("show lldp neighbors")
                conn.close()

                # Extreme show lldp neighbors tabular parse:
                # Port  Chassis ID  Port ID  TTL  Age  System Name
                for line in lldp_out.splitlines():
                    cols = line.split()
                    # Satır: port numarası (rakam) ile başlamalı
                    if not cols or not cols[0].isdigit():
                        continue
                    # En az 6 sütun: port, chassis_id, port_id, ttl, age, sys_name
                    if len(cols) < 6:
                        continue
                    local_port  = cols[0]
                    remote_port = cols[2]
                    sys_name    = cols[5] if len(cols) > 5 else ""
                    if sys_name and sys_name != "0":
                        neighbors.append({
                            "remote_host": sys_name.split(".")[0],
                            "local_port":  local_port,
                            "remote_port": remote_port,
                            "platform": "", "capabilities": "",
                            "protocol": "LLDP",
                        })

                _save_and_done()
            except Exception as e:
                _job_fail(job_id, str(e))
            return

        # ── Ruijie Networks RGOS — Paramiko ───────────────────
        elif "ruijie" in dt or "rgos" in dt:
            try:
                conn = _paramiko.SSHClient()
                conn.set_missing_host_key_policy(_paramiko.AutoAddPolicy())
                conn.connect(ip, port=22,
                             username=cred.get("username",""), password=cred.get("password",""),
                             timeout=30, look_for_keys=False, allow_agent=False)
                shell = conn.invoke_shell(width=512, height=9999)
                shell.settimeout(60)
                time.sleep(2)
                shell.recv(65535)

                def _send(cmd, wait=2):
                    shell.send(cmd + "\n")
                    time.sleep(wait)
                    parts = []
                    deadline = time.time() + 30
                    while time.time() < deadline:
                        if shell.recv_ready():
                            parts.append(shell.recv(65535).decode(errors="replace"))
                            time.sleep(0.3)
                        else:
                            time.sleep(0.5)
                            if not shell.recv_ready():
                                break
                    return "".join(parts)

                lldp_out = _send("show lldp neighbors")
                conn.close()

                # Ruijie show lldp neighbors tabular parse:
                # System Name  Local Intf  Port ID  Capability  Aging-time
                for line in lldp_out.splitlines():
                    # Başlık ve boş satırları atla
                    if not line.strip() or line.strip().startswith("System") \
                            or line.strip().startswith("Capability") \
                            or line.strip().startswith("---"):
                        continue
                    cols = line.split()
                    if len(cols) < 3:
                        continue
                    # sys_name sütunu bazen boşluk içerdiğinden
                    # Local Intf (Te/Gi/Te gibi) sütununu bul
                    local_port  = ""
                    remote_port = ""
                    sys_name    = ""
                    for i, col in enumerate(cols):
                        if re.match(r"^(Te|Gi|Fa|Et|Hu|Tw|Mg)\d", col, re.IGNORECASE):
                            local_port = col
                            sys_name   = " ".join(cols[:i]).strip()
                            if i + 1 < len(cols):
                                remote_port = cols[i + 1]
                            break
                    if local_port and sys_name and sys_name.lower() not in ("unknown", ""):
                        neighbors.append({
                            "remote_host": sys_name.split(".")[0],
                            "local_port":  local_port,
                            "remote_port": remote_port,
                            "platform": "", "capabilities": "",
                            "protocol": "LLDP",
                        })

                _save_and_done()
            except Exception as e:
                _job_fail(job_id, str(e))
            return

        # ── Netmiko destekli cihazlar (Cisco, Huawei, vb.) ───
        try:
            conn = ConnectHandler(
                device_type=device["device_type"], host=ip,
                username=cred.get("username",""), password=cred.get("password",""),
                timeout=30,
            )

            if "cisco" in dt:
                # CDP
                cdp_out = conn.send_command("show cdp neighbors detail", read_timeout=60)
                # LLDP (fallback)
                lldp_out = ""
                try:
                    lldp_out = conn.send_command("show lldp neighbors detail", read_timeout=60)
                except Exception:
                    pass
                # Port-channel + VLAN
                po_out = ""
                vlan_out = ""
                try:
                    po_out   = conn.send_command("show etherchannel summary", read_timeout=60)
                    vlan_out = conn.send_command("show interfaces trunk", read_timeout=60)
                except Exception:
                    pass
                conn.disconnect()

                # CDP parse
                cdp_blocks = re.split(r"-{10,}", cdp_out)
                for blk in cdp_blocks:
                    dev_m   = re.search(r"Device ID:\s*(\S+)", blk)
                    iface_m = re.search(r"Interface:\s*(\S+),\s*Port ID.*?:\s*(\S+)", blk)
                    plat_m  = re.search(r"Platform:\s*([^\n,]+)", blk)
                    cap_m   = re.search(r"Capabilities:\s*(.+)", blk)
                    if dev_m and iface_m:
                        neighbors.append({
                            "remote_host": dev_m.group(1).split(".")[0],
                            "local_port":  iface_m.group(1),
                            "remote_port": iface_m.group(2),
                            "platform":    plat_m.group(1).strip() if plat_m else "",
                            "capabilities": cap_m.group(1).strip() if cap_m else "",
                            "protocol":    "CDP",
                        })

                # LLDP parse (CDP yoksa)
                if not neighbors and lldp_out:
                    lldp_blks = re.split(r"-{5,}", lldp_out)
                    for blk in lldp_blks:
                        sys_m = re.search(r"System Name:\s*(\S+)", blk)
                        lp_m  = re.search(r"Local Intf:\s*(\S+)", blk)
                        rp_m  = re.search(r"Port id:\s*(\S+)", blk)
                        if sys_m and lp_m:
                            neighbors.append({
                                "remote_host": sys_m.group(1).split(".")[0],
                                "local_port":  lp_m.group(1),
                                "remote_port": rp_m.group(1) if rp_m else "",
                                "platform": "", "capabilities": "",
                                "protocol": "LLDP",
                            })

                # Port-channel parse
                for line in po_out.splitlines():
                    m = re.match(r"\s*(\d+)\s+(Po\d+)\S*\s+\S+\s+(.+)", line)
                    if m:
                        po_name = m.group(2)
                        members = re.findall(r"((?:Gi|Fa|Te|Hu|Et)\S+)", m.group(3))
                        portchannels[po_name] = {"members": members, "vlans": []}

                # VLAN trunk parse
                cur_iface = None
                for line in vlan_out.splitlines():
                    iface_m = re.match(r"^(\S+)\s+\S+\s+trunking", line)
                    if iface_m:
                        cur_iface = iface_m.group(1)
                    vlan_m = re.match(r"^\s+([\d,\-]+)\s*$", line)
                    if vlan_m and cur_iface:
                        for po_name, po_data in portchannels.items():
                            if cur_iface in po_data["members"] or cur_iface == po_name:
                                po_data["vlans"].extend(vlan_m.group(1).split(","))

            elif "huawei" in dt:
                lldp_out = conn.send_command("display lldp neighbor brief", read_timeout=60)
                lacp_out = ""
                try:
                    lacp_out = conn.send_command("display eth-trunk", read_timeout=60)
                except Exception:
                    pass
                conn.disconnect()

                for line in lldp_out.splitlines():
                    cols = line.split()
                    if len(cols) >= 4 and not line.startswith("Local"):
                        neighbors.append({
                            "local_port":  cols[0],
                            "remote_host": cols[2],
                            "remote_port": cols[3] if len(cols) > 3 else "",
                            "platform": "", "capabilities": "",
                            "protocol": "LLDP",
                        })

                cur_trunk = None
                for line in lacp_out.splitlines():
                    tm = re.match(r"Eth-Trunk(\d+)", line)
                    if tm:
                        cur_trunk = f"Eth-Trunk{tm.group(1)}"
                        portchannels[cur_trunk] = {"members": [], "vlans": []}
                    mem_m = re.search(r"(GE|XGE|100GE|40GE)\S+", line)
                    if mem_m and cur_trunk:
                        portchannels[cur_trunk]["members"].append(mem_m.group(0))

            else:
                conn.disconnect()

            _save_and_done()

        except (NetmikoAuthenticationException, NetmikoTimeoutException) as e:
            _job_fail(job_id, f"SSH bağlantı hatası: {e}")
        except Exception as e:
            _job_fail(job_id, str(e))

    threading.Thread(target=run, daemon=True).start()
    return jsonify({"job_id": job_id})

# ══════════════════════════════════════════════════════════
# API — Dashboard drilldown (stats detayı)
# ══════════════════════════════════════════════════════════

@app.route("/api/stats/detail/<stat_type>")
@login_required
def api_stats_detail(stat_type):
    if stat_type == "users":
        if session.get("role") != "admin":
            return jsonify({"error": "Yönetici yetkisi gerekli"}), 403
        users = _load_users()
        result = [{"username": "admin", "role": "admin", "system": True}]
        result += [{"username": u, "role": d.get("role","user"), "system": False}
                   for u, d in users.items()]
        return jsonify(result)

    if stat_type == "inventory":
        inv = _load_inventory()
        # Marka gruplaması
        dd_data = _load_device_details()
        by_brand = {}
        for d in inv:
            dt    = d.get("device_type", "unknown")
            brand = ("Fortinet"         if "forti"      in dt else
                     "Cisco"            if "cisco"      in dt else
                     "Huawei"           if "huawei"     in dt else
                     "H3C"              if "h3c"        in dt or "comware" in dt else
                     "Extreme Networks" if "extreme"    in dt else
                     "Ruijie"           if "ruijie"     in dt or "rgos" in dt else
                     "F5"               if "f5"         in dt or "bigip" in dt else
                     "Dell"             if "dell"       in dt else
                     "HP"               if "hp"         in dt else dt.title())
            # Model: device_details'dan al, yoksa device_type
            ip    = d.get("ip", "")
            model = (dd_data.get(ip, {}).get("model") or
                     d.get("model") or dt)
            if model:
                model = str(model).strip()
            if not model:
                model = dt
            by_brand.setdefault(brand, {}).setdefault(model, []).append(d["name"])
        # Tag gruplaması
        by_tag = {}
        for d in inv:
            for t in d.get("tags", []):
                by_tag.setdefault(t, []).append(d["name"])
        # Credential gruplaması
        by_cred = {}
        for d in inv:
            c = d.get("credential_id","—")
            by_cred.setdefault(c, []).append(d["name"])
        return jsonify({"by_brand": by_brand, "by_tag": by_tag, "by_cred": by_cred, "total": len(inv)})

    if stat_type == "backups":
        return jsonify(_list_backups())

    if stat_type == "exclude":
        return jsonify(_load_exclude())

    return jsonify({"error": "Bilinmeyen istatistik"}), 400

# ══════════════════════════════════════════════════════════
# API — Backup schedule
# ══════════════════════════════════════════════════════════

SCHEDULE_PATH = _BASE / "data" / "backup_schedule.json"

def _load_schedule() -> dict:
    if not SCHEDULE_PATH.exists():
        return {}
    return json.loads(SCHEDULE_PATH.read_text(encoding="utf-8"))

def _save_schedule(s: dict) -> None:
    SCHEDULE_PATH.write_text(json.dumps(s, indent=2, ensure_ascii=False), encoding="utf-8")

_DEFAULT_SCHEDULE: dict = {"enabled": True, "day": "sunday", "hour": 0,
                           "minute": 0, "mode": "full", "tag": ""}

def _default_schedule() -> dict:
    """Her çağrıda yeni kopya döndür (mutation güvenliği)."""
    return dict(_DEFAULT_SCHEDULE)

@app.route("/api/schedule")
@login_required
def api_schedule_get():
    sch = _load_schedule()
    inv = _load_inventory()
    # Her cihaz için schedule var mı? Yoksa default döndür
    result = {}
    default = _default_schedule()
    for d in inv:
        ip = d["ip"]
        result[ip] = sch.get(ip, dict(default, name=d["name"], device_type=d.get("device_type","")))
    return jsonify({"global": sch.get("__global__", default), "devices": result})

@app.route("/api/schedule", methods=["POST"])
@login_required
@admin_required
def api_schedule_save():
    d = request.get_json() or {}
    sch = _load_schedule()
    if "global" in d:
        sch["__global__"] = d["global"]
    if "devices" in d:
        for ip, cfg in d["devices"].items():
            sch[ip] = cfg
    _save_schedule(sch)
    _update_scheduler_jobs()
    return jsonify({"success": True})

@app.route("/api/schedule/<path:ip>", methods=["PUT"])
@login_required
@admin_required
def api_schedule_device(ip):
    """
    Cihaz schedule'ını kaydeder ve uygun zamanda backup'ı tetikler.

    Karar ağacı (kaydet tuşuna her basıldığında):
      - Gün bugün değil          → sadece kaydet, doğru günde cron çalışır
      - Gün bugün, saat geçmiş   → hemen backup al (geçti, bir daha bu hafta yok)
      - Gün bugün, saat ileride  → o saate one-shot APScheduler job ekle
      - run_now=True gönderildi  → her koşulda hemen al
    """
    from datetime import datetime as _dt, timedelta as _td

    sch  = _load_schedule()
    data = request.get_json()
    if not data or not isinstance(data, dict):
        return jsonify({"error": "Gecersiz JSON"}), 400
    inv = _load_inventory()
    dev = next((d for d in inv if d.get("ip") == ip), None)
    if not dev:
        return jsonify({"error": "Cihaz bulunamadı"}), 404
    data["name"]        = dev.get("name", ip)
    data["device_type"] = data.get("device_type") or dev.get("device_type", "")
    sch[ip] = data
    _save_schedule(sch)

    # Cron job'larını güncelle (scheduler restart ETMEDEn)
    try:
        _update_scheduler_jobs()
    except Exception:
        pass

    run_now        = data.get("run_now", False)
    backup_started = False

    if data.get("enabled", True):
        now       = _dt.now()
        day_map   = {"sunday":6,"monday":0,"tuesday":1,"wednesday":2,
                     "thursday":3,"friday":4,"saturday":5}
        sched_day = day_map.get(data.get("day", "sunday").lower(), 6)
        sched_h   = int(data.get("hour",   0))
        sched_m   = int(data.get("minute", 0))

        today_is_sched_day = (now.weekday() == sched_day)

        if run_now or (today_is_sched_day and (now.hour, now.minute) >= (sched_h, sched_m)):
            # Saat geçmiş veya run_now → hemen arka planda başlat
            run_now = True
        # Saat ileride ise ek bir şey yapmaya gerek yok —
        # cron tick (backup_tick) o dakikada zaten çalışacak

    if run_now:
        import threading as _thr
        v = get_vault()
        if v:
            _dev = dev
            def _do_now():
                try:
                    backup_svc.perform_backup([_dev], v.vault, _load_commands())
                except Exception:
                    pass
            _thr.Thread(target=_do_now, daemon=True).start()
        backup_started = True

    return jsonify({
        "success":        True,
        "backup_started": backup_started,
    })

# ── APScheduler kurulumu ──────────────────────────────────

def _run_scheduled_backup():
    """
    Her dakika APScheduler tarafından tetiklenir.
    datetime.now() (yerel saat) ile schedule karşılaştırır —
    timezone farkından tamamen bağımsız çalışır.
    """
    now    = datetime.now()
    hour   = now.hour
    minute = now.minute

    v = get_vault()
    if not v:
        return

    try:
        inv  = _load_inventory()
        sch  = _load_schedule()
        cmds = _load_commands()
    except Exception:
        return

    default = _default_schedule()
    day_map = {"sunday":6,"monday":0,"tuesday":1,"wednesday":2,
               "thursday":3,"friday":4,"saturday":5}

    devices_to_backup = []
    for d in inv:
        cfg = sch.get(d["ip"], default)
        if not cfg.get("enabled", True):
            continue
        sched_day  = day_map.get(cfg.get("day", "sunday").lower(), 6)
        dev_hour   = int(cfg.get("hour",   default["hour"]))
        dev_minute = int(cfg.get("minute", default["minute"]))
        if now.weekday() == sched_day and dev_hour == hour and dev_minute == minute:
            devices_to_backup.append(d)

    if not devices_to_backup:
        return

    ts    = now.strftime("%H:%M")
    names = ", ".join(d["name"] for d in devices_to_backup[:5])
    if len(devices_to_backup) > 5:
        names += f" +{len(devices_to_backup)-5}"

    print(f"  [SCHEDULER] {ts} — {len(devices_to_backup)} cihaz backup başlıyor", flush=True)
    _push_notification(f"💾 Scheduled backup başladı — {names}", "info")

    try:
        backup_svc.perform_backup(devices_to_backup, v.vault, cmds)
        print(f"  [SCHEDULER] Backup tamamlandı ({len(devices_to_backup)} cihaz)", flush=True)
        _push_notification(
            f"✅ Scheduled backup tamamlandı — {len(devices_to_backup)} cihaz ({ts})", "ok"
        )
    except Exception as exc:
        print(f"  [SCHEDULER] Backup HATA: {exc}", flush=True)
        _push_notification(f"❌ Scheduled backup hatası: {exc}", "err")

_scheduler = None

def _setup_scheduler():
    """APScheduler başlatır. Yerel saat için tzlocal kullanır."""
    global _scheduler
    if _scheduler and _scheduler.running:
        _update_scheduler_jobs()
        return
    local_tz = None
    try:
        from tzlocal import get_localzone
        local_tz = get_localzone()
    except Exception:
        pass
    from apscheduler.schedulers.background import BackgroundScheduler
    sched = BackgroundScheduler(timezone=local_tz)
    sched.start()
    _scheduler = sched
    _update_scheduler_jobs()
    print(f"  Scheduler baslatildi — timezone: {local_tz or 'UTC'}", flush=True)


def _update_scheduler_jobs():
    """Scheduler job'larını günceller. Tek minutely job ile timezone bağımsız çalışır."""
    global _scheduler
    if not _scheduler or not _scheduler.running:
        return

    # Her dakika çalışan tek backup kontrol job'u
    _scheduler.add_job(
        _run_scheduled_backup,
        "cron",
        minute="*",           # her dakika tetikle
        id="backup_tick",
        replace_existing=True,
    )

    # Status check — sabit 03:00 (yerel saat, timezone fark etmez — dakika bazlı kontrol)
    _scheduler.add_job(_run_scheduled_status_check, "cron", hour=3, minute=0,
                       id="nightly_status_check", replace_existing=True)

# Uygulama başladığında scheduler'ı başlat
try:
    _setup_scheduler()
except Exception as _e:
    print(f"  ⚠️  Scheduler başlatılamadı: {_e}", flush=True)


# Push notification queue — browser SSE clients subscribe to this
import queue as _notif_queue_mod
_notif_queues: list = []   # list of queue.Queue objects, one per open SSE client
_notif_lock   = threading.Lock()


def _push_notification(message: str, ntype: str = "ok") -> None:
    """Tüm açık SSE bağlantılarına anlık bildirim gönderir."""
    import json as _json
    payload = _json.dumps({"message": message, "type": ntype,
                           "ts": datetime.now().strftime("%H:%M:%S")})
    with _notif_lock:
        dead = []
        for q in _notif_queues:
            try:
                q.put_nowait(payload)
            except Exception:
                dead.append(q)
        for q in dead:
            _notif_queues.remove(q)





@app.route("/api/notifications/stream")
@login_required
def api_notifications_stream():
    """SSE akışı — her bağlanan tarayıcı sekmesi buraya subscribe olur."""
    from flask import Response
    q = _notif_queue_mod.Queue(maxsize=50)
    with _notif_lock:
        _notif_queues.append(q)

    def generate():
        try:
            while True:
                try:
                    data = q.get(timeout=30)
                    yield f"data: {data}\n\n"
                except _notif_queue_mod.Empty:
                    yield "data: {}\n\n"   # heartbeat
        finally:
            with _notif_lock:
                if q in _notif_queues:
                    _notif_queues.remove(q)

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ══════════════════════════════════════════════════════════
# API — Kullanıcı şifre değiştirme (kendi şifresi)
# ══════════════════════════════════════════════════════════

@app.route("/api/profile/password", methods=["PUT"])
@login_required
def api_profile_chpw():
    username = session.get("username")
    if username == "admin":
        return jsonify({"error": "Admin şifresi vault key'i ile aynıdır, buradan değiştirilemez"}), 400
    d = request.get_json() or {}
    old_pw = d.get("old_password", "")
    new_pw = d.get("new_password", "")
    if not old_pw or not new_pw:
        return jsonify({"error": "Eski ve yeni şifre gerekli"}), 400
    users = _load_users()
    if username not in users:
        return jsonify({"error": "Kullanıcı bulunamadı"}), 404
    if users[username]["password_hash"] != _hash_pw(old_pw):
        return jsonify({"error": "Mevcut şifre hatalı"}), 401
    if len(new_pw) < 6:
        return jsonify({"error": "Yeni şifre en az 6 karakter olmalı"}), 400
    users[username]["password_hash"] = _hash_pw(new_pw)
    _save_users(users)
    return jsonify({"success": True})

# ══════════════════════════════════════════════════════════
# API — Backup indirme
# ══════════════════════════════════════════════════════════

@app.route("/api/backup/download")
@login_required
def api_backup_download():
    """Backup dosyasını indirir.
    Parametreler: ?date=2026-03-14&name=xxx.conf
    Eski uyumluluk için ?path= da kabul edilir.
    """
    date = request.args.get("date", "")
    name = request.args.get("name", "")

    if not name:
        raw_path = request.args.get("path", "")
        if raw_path:
            import pathlib as _pl2
            p = _pl2.PurePosixPath(raw_path.replace(chr(92)+chr(92), "/").replace(chr(92), "/"))
            name = p.name
            if len(p.parts) >= 2:
                date = p.parts[-2]

    if not name:
        return jsonify({"error": "name gerekli"}), 400

    f = _resolve_backup_file(date, name)
    if f is None:
        return jsonify({"error": "Geçersiz dosya yolu"}), 400
    if not f.exists() or not f.is_file():
        if not date:
            for day_dir in BACKUP_DIR.iterdir():
                candidate = (day_dir / name).resolve()
                if candidate.exists() and str(candidate).startswith(str(BACKUP_DIR.resolve())):
                    f = candidate
                    break
        if not f or not f.exists():
            return jsonify({"error": "Dosya bulunamadı"}), 404
    return send_file(str(f), as_attachment=True, download_name=f.name)


@app.route("/api/backup/download-all")
@login_required
def api_backup_download_all():
    """Tüm backup dosyalarını zip olarak indirir.
    Opsiyonel: ?date=2026-03-14 → sadece o günün backupları
    """
    import zipfile, io
    date_filter = request.args.get("date", "")

    zip_buf = io.BytesIO()
    count   = 0
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        if not BACKUP_DIR.exists():
            return jsonify({"error": "Backup klasörü bulunamadı"}), 404
        for day_dir in sorted(BACKUP_DIR.iterdir()):
            if not day_dir.is_dir():
                continue
            if date_filter and day_dir.name != date_filter:
                continue
            for f in sorted(day_dir.iterdir()):
                if f.is_file():
                    arcname = f"{day_dir.name}/{f.name}"
                    zf.write(str(f), arcname)
                    count += 1

    if count == 0:
        return jsonify({"error": "İndirilecek backup bulunamadı"}), 404

    zip_buf.seek(0)
    zip_name = f"backups_{date_filter or 'all'}.zip"
    return send_file(
        zip_buf,
        mimetype="application/zip",
        as_attachment=True,
        download_name=zip_name
    )

# ══════════════════════════════════════════════════════════
# API — SSH log yönetimi
# ══════════════════════════════════════════════════════════

@app.route("/api/ssh-logs")
@login_required
def api_ssh_logs():
    """SSH session log listesi."""
    logs = []
    for f in sorted(SSH_LOG_DIR.glob("*.log"), reverse=True):
        try:
            stat = f.stat()
            logs.append({
                "name": f.name,
                "size": stat.st_size,
                "date": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                "path": str(f),
            })
        except Exception:
            continue
    return jsonify({"logs": logs})

@app.route("/api/ssh-logs/download")
@login_required
def api_ssh_log_download():
    """SSH log dosyasını indir."""
    name = request.args.get("name", "")
    if not name or "/" in name or chr(92) in name:
        return jsonify({"error": "Geçersiz dosya adı"}), 400
    f = SSH_LOG_DIR / name
    if not f.exists():
        return jsonify({"error": "Bulunamadı"}), 404
    return send_file(str(f), as_attachment=True, download_name=f.name)

@app.route("/api/ssh-logs/<name>", methods=["DELETE"])
@login_required
def api_ssh_log_delete(n):
    """SSH log dosyasını sil."""
    if "/" in n or chr(92) in n:
        return jsonify({"error": "Geçersiz"}), 400
    f = SSH_LOG_DIR / n
    if f.exists():
        f.unlink()
    return jsonify({"success": True})

# ══════════════════════════════════════════════════════════
# WebSocket — SSH Terminal
# ══════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════
# SSH Terminal — SSE + POST (platform bağımsız)
# ══════════════════════════════════════════════════════════
import queue as _queue

_ssh_sessions: dict[str, dict] = {}
_ssh_lock = threading.Lock()

def _ssh_session_new(sid: str, device: dict, cred: dict) -> None:
    """Yeni SSH session başlatır, arka plan thread'inde çalışır."""
    import paramiko, select as _sel, re as _re
    ip   = device["ip"]
    user = cred.get("username", "")
    pwd  = cred.get("password", "")
    port = int(device.get("ssh_port", 22))
    name = device.get("name", ip)

    sess = _ssh_sessions[sid]
    q    = sess["q"]          # output queue → SSE
    iq   = sess["iq"]         # input queue  ← POST

    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_name = f"{name}_{ip}_{ts}.log"
    log_path = SSH_LOG_DIR / log_name
    log_buf  = []

    def emit(t: str, **kw):
        q.put({"type": t, **kw})

    def log(s: str):
        log_buf.append(s)

    def strip_ansi(s: str) -> str:
        return _re.sub(
            r"\[[0-9;]*[mABCDEFGHJKSTfhilmnprsu]"
            r"|\[[?][0-9;]*[hl]|\([A-Z]|[=>]", "", s)

    emit("status", msg=f"🔌 {ip}:{port} bağlanılıyor…")
    log(f"=== SSH Session: {name} ({ip}:{port}) ===\n")
    log(f"Başlangıç: {datetime.now().isoformat()}\n{'='*60}\n\n")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(ip, port=port, username=user, password=pwd,
                       timeout=15, auth_timeout=15,
                       look_for_keys=False, allow_agent=False)
    except Exception as e:
        emit("error", msg=f"Bağlantı hatası: {e}")
        log(f"\n[HATA] {e}\n")
        log_path.write_text("".join(log_buf), encoding="utf-8", errors="replace")
        with _ssh_lock:
            _ssh_sessions[sid]["closed"] = True
            _ssh_sessions[sid]["log"] = log_name
        return

    emit("connected", msg=f"✅ {name} ({ip}) bağlı", log=log_name)
    sess["log"] = log_name

    chan = client.invoke_shell(term="xterm-256color", width=220, height=50)
    chan.settimeout(0.05)

    try:
        while not sess.get("closed"):
            # Read from device
            try:
                data = chan.recv(4096)
                if not data:
                    break
                text = data.decode("utf-8", errors="replace")
                emit("data", d=text)
                log(strip_ansi(text))
            except Exception:
                pass

            # Send pending input to device
            while True:
                try:
                    inp = iq.get_nowait()
                    if inp is None:          # close signal
                        break
                    chan.send(inp)
                    if inp not in ("\r", "\n", "\r\n"):
                        log(inp)
                except _queue.Empty:
                    break
    except Exception:
        pass
    finally:
        try: chan.close()
        except Exception: pass
        try: client.close()
        except Exception: pass
        log(f"\n\n=== Oturum sona erdi: {datetime.now().isoformat()} ===\n")
        log_path.write_text("".join(log_buf), encoding="utf-8", errors="replace")
        with _ssh_lock:
            _ssh_sessions[sid]["closed"] = True
            _ssh_sessions[sid]["log"] = log_name
        emit("disconnected", log=log_name)


@app.route("/api/ssh/test")
@login_required
def api_ssh_test():
    """SSH bağlantı testi - cihaz erişilebilirliğini kontrol eder."""
    import socket
    idx = int(request.args.get("idx", -1))
    inv = _load_inventory()
    if idx < 0 or idx >= len(inv):
        return jsonify({"error": "Cihaz bulunamadı"}), 404
    device = inv[idx]
    ip = device["ip"]
    port = int(device.get("ssh_port", 22))
    # TCP bağlantı testi
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        result = s.connect_ex((ip, port))
        s.close()
        tcp_ok = result == 0
    except Exception as e:
        tcp_ok = False
    # Vault kontrolü
    v = get_vault()
    cred_id = device.get("credential_id", "")
    has_cred = bool(v and cred_id and cred_id in v.vault)
    return jsonify({
        "device": device["name"],
        "ip": ip,
        "port": port,
        "tcp_open": tcp_ok,
        "vault_ok": bool(v),
        "cred_ok": has_cred,
        "cred_id": cred_id,
        "device_type": device.get("device_type", ""),
    })

@app.route("/api/ssh/<int:idx>/start", methods=["POST"])
@login_required
def api_ssh_start(idx):
    v = get_vault()
    if not v:
        return jsonify({"error": "Vault açık değil"}), 500
    inv = _load_inventory()
    if idx < 0 or idx >= len(inv):
        return jsonify({"error": "Cihaz bulunamadı"}), 404
    device   = inv[idx]
    cred_id  = device.get("credential_id", "")
    if not cred_id or cred_id not in v.vault:
        return jsonify({"error": f"Credential bulunamadı: {cred_id}"}), 400
    cred = v.vault[cred_id]
    sid  = secrets.token_hex(10)
    with _ssh_lock:
        _ssh_sessions[sid] = {
            "q": _queue.Queue(),
            "iq": _queue.Queue(),
            "closed": False,
            "log": None,
            "idx": idx,
            "user": session.get("username", ""),
        }
    threading.Thread(target=_ssh_session_new, args=(sid, device, cred), daemon=True).start()
    return jsonify({"sid": sid})


@app.route("/api/ssh/<sid>/stream")
@login_required
def api_ssh_stream(sid):
    """SSE akışı: terminale gelen veriler → tarayıcı."""
    from flask import Response
    sess = _ssh_sessions.get(sid)
    if not sess:
        return jsonify({"error": "Session bulunamadı"}), 404

    def generate():
        while True:
            try:
                msg = sess["q"].get(timeout=25)
                yield f"data: {json.dumps(msg)}\n\n"
                if msg.get("type") in ("disconnected", "error"):
                    break
            except _queue.Empty:
                # heartbeat
                yield "data: {}\n\n"
    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/api/ssh/<sid>/input", methods=["POST"])
@login_required
def api_ssh_input(sid):
    sess = _ssh_sessions.get(sid)
    if not sess:
        return jsonify({"error": "Session yok"}), 404
    data = request.get_json() or {}
    inp  = data.get("d", "")
    if inp:
        sess["iq"].put(inp)
    return jsonify({"ok": True})


@app.route("/api/ssh/<sid>/resize", methods=["POST"])
@login_required
def api_ssh_resize(sid):
    # Resize is handled in the SSH thread via a special queue message
    return jsonify({"ok": True})


@app.route("/api/ssh/<sid>/close", methods=["POST"])
@login_required
def api_ssh_close(sid):
    sess = _ssh_sessions.get(sid)
    if sess:
        sess["iq"].put(None)
        sess["closed"] = True
    return jsonify({"ok": True})



# ══════════════════════════════════════════════════════════
# HTML Şablonu
# ══════════════════════════════════════════════════════════
_INLINE_TEMPLATE = r"""<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Octopus NMS</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&family=Syne:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#090b0f;--bg2:#0e1118;--bg3:#141820;--bg4:#1a2030;
  --border:#1c2233;--border2:#243050;
  --accent:#00d4aa;--accent2:#3b82f6;--accent3:#f97316;
  --text:#dde4f0;--text2:#7a8799;--text3:#3a4558;
  --danger:#ef4444;--warn:#f59e0b;--ok:#22c55e;
  --r:8px;--r2:12px;
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;background:var(--bg);color:var(--text);font-family:'JetBrains Mono',monospace;font-size:13px;line-height:1.5}
::-webkit-scrollbar{width:4px;height:4px}::-webkit-scrollbar-track{background:var(--bg2)}::-webkit-scrollbar-thumb{background:var(--border2);border-radius:2px}
/* LOGIN */
#login-screen{display:flex;align-items:center;justify-content:center;min-height:100vh;
  background:radial-gradient(ellipse at 25% 60%,rgba(0,212,170,.06) 0%,transparent 55%),
             radial-gradient(ellipse at 80% 20%,rgba(59,130,246,.05) 0%,transparent 50%),var(--bg)}
.lbox{width:380px;padding:48px 40px;background:var(--bg2);border:1px solid var(--border);border-radius:var(--r2);position:relative;overflow:hidden}
.lbox::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,var(--accent),var(--accent2),transparent)}
.llogo{text-align:center;margin-bottom:36px}
.llogo .li{font-size:44px;display:block;margin-bottom:10px;filter:drop-shadow(0 0 24px rgba(0,212,170,.5));animation:glow 3s ease-in-out infinite}
@keyframes glow{0%,100%{filter:drop-shadow(0 0 16px rgba(0,212,170,.4))}50%{filter:drop-shadow(0 0 32px rgba(0,212,170,.9))}}
.llogo h1{font-family:'Syne',sans-serif;font-size:26px;font-weight:800;letter-spacing:6px;background:linear-gradient(135deg,var(--accent),var(--accent2));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.llogo p{color:var(--text2);font-size:11px;letter-spacing:2px;margin-top:4px;text-transform:uppercase}
.fg{margin-bottom:14px}.fg label{display:block;color:var(--text2);font-size:10px;letter-spacing:1px;text-transform:uppercase;margin-bottom:5px}
.fg input,.fg select,.fg textarea{width:100%;padding:10px 14px;background:var(--bg3);border:1px solid var(--border);border-radius:var(--r);color:var(--text);font-family:inherit;font-size:13px;outline:none;transition:border-color .2s}
.fg input:focus,.fg select:focus,.fg textarea:focus{border-color:var(--accent)}
.errmsg{color:var(--danger);font-size:11px;margin-top:10px;text-align:center;min-height:16px}
/* BUTTONS */
.btn{display:inline-flex;align-items:center;gap:6px;padding:9px 16px;border:none;border-radius:var(--r);font-family:inherit;font-size:12px;font-weight:600;cursor:pointer;transition:all .18s;letter-spacing:.4px;white-space:nowrap}
.btn-p{background:linear-gradient(135deg,var(--accent),#00a87d);color:#000;width:100%;justify-content:center}
.btn-p:hover{opacity:.9;transform:translateY(-1px);box-shadow:0 4px 20px rgba(0,212,170,.25)}
.btn-s{background:var(--bg3);border:1px solid var(--border2);color:var(--text)}.btn-s:hover{border-color:var(--accent);color:var(--accent)}
.btn-b{background:rgba(59,130,246,.15);border:1px solid rgba(59,130,246,.3);color:var(--accent2)}.btn-b:hover{background:rgba(59,130,246,.25)}
.btn-d{background:rgba(239,68,68,.15);border:1px solid rgba(239,68,68,.3);color:var(--danger)}.btn-d:hover{background:rgba(239,68,68,.25)}
.btn-o{background:rgba(249,115,22,.15);border:1px solid rgba(249,115,22,.3);color:var(--accent3)}.btn-o:hover{background:rgba(249,115,22,.25)}
.btn-g{background:rgba(168,85,247,.15);border:1px solid rgba(168,85,247,.3);color:#a855f7}.btn-g:hover{background:rgba(168,85,247,.25)}
.btn-sm{padding:5px 10px;font-size:11px}.btn-xs{padding:3px 7px;font-size:10px}.btn-i{padding:5px 7px}
.btn:disabled{opacity:.35;cursor:not-allowed;transform:none!important}
/* APP LAYOUT */
#app{display:none;height:100vh;flex-direction:column}#app.v{display:flex}
.topbar{height:50px;display:flex;align-items:center;padding:0 18px;background:var(--bg2);border-bottom:1px solid var(--border);flex-shrink:0;gap:12px;position:relative}
.tlogo{font-family:'Syne',sans-serif;font-weight:800;font-size:15px;letter-spacing:4px;background:linear-gradient(135deg,var(--accent),var(--accent2));-webkit-background-clip:text;-webkit-text-fill-color:transparent;display:flex;align-items:center;gap:6px;flex-shrink:0}
.tlogo .ti{-webkit-text-fill-color:initial;font-size:18px}
.tnav{display:flex;gap:2px;overflow-x:auto}
.nb{padding:6px 12px;border:none;background:transparent;color:var(--text2);font-family:inherit;font-size:11px;cursor:pointer;border-radius:6px;transition:all .18s;letter-spacing:.4px;white-space:nowrap;display:flex;align-items:center;gap:5px}
.nb:hover{background:var(--bg4);color:var(--text)}.nb.act{background:rgba(0,212,170,.1);color:var(--accent)}
.tuser{margin-left:auto;display:flex;align-items:center;gap:10px;flex-shrink:0}
.ubadge{display:flex;align-items:center;gap:6px;padding:4px 11px;background:var(--bg3);border:1px solid var(--border);border-radius:20px;font-size:11px;cursor:pointer;transition:border-color .2s}
.ubadge:hover{border-color:var(--border2)}.ubadge .role{color:var(--accent2);font-weight:600}
/* user dropdown */
.udrop{position:absolute;top:52px;right:18px;background:var(--bg2);border:1px solid var(--border2);border-radius:var(--r);padding:6px;min-width:190px;z-index:200;display:none;box-shadow:0 8px 32px rgba(0,0,0,.5)}
.udrop.open{display:block}
.udrop-item{padding:7px 10px;border-radius:6px;cursor:pointer;font-size:12px;display:flex;align-items:center;gap:8px;color:var(--text2);transition:all .15s}
.udrop-item:hover{background:var(--bg3);color:var(--text)}
.udrop-sep{height:1px;background:var(--border);margin:4px 0}
.body{flex:1;overflow:hidden;display:flex}
.pg{display:none;flex:1;overflow-y:auto;padding:22px;animation:fi .2s}
.pg.act{display:block}
@keyframes fi{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}
.sh{display:flex;align-items:center;justify-content:space-between;margin-bottom:18px;padding-bottom:14px;border-bottom:1px solid var(--border)}
.st{font-family:'Syne',sans-serif;font-size:18px;font-weight:700;display:flex;align-items:center;gap:8px}
.ss{font-family:'Syne',sans-serif;font-size:14px;font-weight:600;display:flex;align-items:center;gap:6px;margin:18px 0 12px;color:var(--text)}
/* STATS */
.sgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:18px}
.sc{background:var(--bg2);border:1px solid var(--border);border-radius:var(--r2);padding:18px;position:relative;overflow:hidden;cursor:pointer;transition:all .2s}
.sc:hover{border-color:var(--border2);transform:translateY(-1px)}
.sc::after{content:'';position:absolute;top:0;left:0;right:0;height:2px}
.sc.g::after{background:linear-gradient(90deg,var(--accent),transparent)}.sc.b::after{background:linear-gradient(90deg,var(--accent2),transparent)}
.sc.o::after{background:linear-gradient(90deg,var(--accent3),transparent)}.sc.r::after{background:linear-gradient(90deg,var(--danger),transparent)}
.sc.gr::after{background:linear-gradient(90deg,#a855f7,transparent)}
.sv{font-family:'Syne',sans-serif;font-size:28px;font-weight:800}.sl{color:var(--text2);font-size:10px;letter-spacing:1px;text-transform:uppercase;margin-top:2px}
.sic{position:absolute;right:14px;top:14px;font-size:24px;opacity:.15}
/* MODULE CARDS */
.mgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:10px}
.mcard{background:var(--bg2);border:1px solid var(--border);border-radius:var(--r2);padding:18px;cursor:pointer;transition:all .2s;position:relative;overflow:hidden}
.mcard:hover{border-color:var(--border2);transform:translateY(-2px);box-shadow:0 6px 24px rgba(0,0,0,.3)}
.mcard:hover .mArr{color:var(--accent);transform:translateY(-50%) translateX(3px)}
.mico{font-size:28px;margin-bottom:8px}.mname{font-family:'Syne',sans-serif;font-weight:700;font-size:13px;margin-bottom:4px}
.mdesc{color:var(--text2);font-size:11px;line-height:1.5}.mArr{position:absolute;right:14px;top:50%;transform:translateY(-50%);color:var(--text3);font-size:16px;transition:all .2s}
/* CARD */
.card{background:var(--bg2);border:1px solid var(--border);border-radius:var(--r2);margin-bottom:14px}
.cp{padding:18px}.chdr{display:flex;align-items:center;justify-content:space-between;padding:14px 18px;border-bottom:1px solid var(--border)}
.ct{color:var(--text2);font-size:11px;letter-spacing:1px;text-transform:uppercase;font-weight:500}
/* TABLE */
.tw{overflow-x:auto}table{width:100%;border-collapse:collapse}
th,td{padding:9px 14px;text-align:left;border-bottom:1px solid var(--border)}
th{color:var(--text2);font-size:10px;letter-spacing:1px;text-transform:uppercase;font-weight:500;white-space:nowrap}
tr:last-child td{border-bottom:none}tr:hover td{background:rgba(255,255,255,.018)}
.ab{display:flex;gap:4px;flex-wrap:nowrap}
/* TAGS */
.tag{display:inline-block;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:600;letter-spacing:.4px;white-space:nowrap}
.tg{background:rgba(0,212,170,.12);color:var(--accent)}.tb{background:rgba(59,130,246,.12);color:var(--accent2)}
.to{background:rgba(249,115,22,.12);color:var(--accent3)}.tr{background:rgba(239,68,68,.12);color:var(--danger)}
.tgr{background:rgba(255,255,255,.07);color:var(--text2)}.tp{background:rgba(168,85,247,.12);color:#a855f7}
/* OVERLAY / MODAL */
.overlay{display:none;position:fixed;inset:0;z-index:100;background:rgba(0,0,0,.75);backdrop-filter:blur(3px);align-items:center;justify-content:center}
.overlay.open{display:flex}
.modal{background:var(--bg2);border:1px solid var(--border2);border-radius:var(--r2);padding:24px;width:520px;max-width:96vw;max-height:88vh;overflow-y:auto;position:relative;animation:mIn .18s ease}
@keyframes mIn{from{opacity:0;transform:scale(.96) translateY(-6px)}to{opacity:1;transform:none}}
.modal.wide{width:720px}.modal.xl{width:920px}
.mt{font-family:'Syne',sans-serif;font-size:15px;font-weight:700;margin-bottom:16px;display:flex;align-items:center;gap:6px}
.mc{position:absolute;top:12px;right:12px;background:none;border:none;color:var(--text2);font-size:18px;cursor:pointer;padding:4px 6px;line-height:1;border-radius:4px}
.mc:hover{color:var(--text);background:var(--bg3)}
.mf{display:flex;gap:8px;justify-content:flex-end;margin-top:16px;padding-top:12px;border-top:1px solid var(--border)}
/* SEARCH */
.sbar{display:flex;gap:8px;margin-bottom:14px}
.sbar input{flex:1;padding:8px 12px;background:var(--bg3);border:1px solid var(--border);border-radius:var(--r);color:var(--text);font-family:inherit;font-size:12px;outline:none}
.sbar input:focus{border-color:var(--accent)}
/* TOAST */
.toasts{position:fixed;top:14px;right:14px;z-index:300;display:flex;flex-direction:column;gap:6px;pointer-events:none}
.toast{padding:9px 14px;border-radius:var(--r);font-size:12px;border-left:3px solid;background:var(--bg2);border-top:1px solid var(--border);border-right:1px solid var(--border);border-bottom:1px solid var(--border);max-width:300px;animation:tIn .2s;box-shadow:0 4px 16px rgba(0,0,0,.4)}
.toast.ok{border-left-color:var(--ok)}.toast.err{border-left-color:var(--danger)}.toast.info{border-left-color:var(--accent2)}
@keyframes tIn{from{opacity:0;transform:translateX(12px)}to{opacity:1;transform:none}}
/* LOG BOX */
.logbox{background:var(--bg);border:1px solid var(--border);border-radius:var(--r);padding:10px 12px;height:260px;overflow-y:auto;font-size:11px;line-height:1.8}
.ll{color:var(--text2)}.ll.ok{color:var(--ok)}.ll.err{color:var(--danger)}.ll.hdr{color:var(--accent);font-weight:600}
/* GRID HELPERS */
.g2{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px}
/* VAULT FIELDS */
.fl{border:1px solid var(--border);border-radius:var(--r);overflow:hidden;margin-bottom:10px}
.fi{display:flex;align-items:center;padding:8px 11px;gap:8px;border-bottom:1px solid var(--border)}.fi:last-child{border-bottom:none}
.fn{color:var(--text2);min-width:110px;font-size:11px;flex-shrink:0}
.fv{flex:1;font-family:inherit;background:var(--bg3);border:1px solid var(--border);border-radius:4px;padding:4px 8px;color:var(--text);font-size:12px;outline:none;width:100%}
.fv:focus{border-color:var(--accent)}
/* PW GEN */
.pwd{background:var(--bg3);border:1px solid var(--border2);border-radius:var(--r);padding:10px 14px;display:flex;align-items:center;gap:8px;margin-bottom:12px}
.pwtxt{flex:1;word-break:break-all;font-size:14px;letter-spacing:.5px;color:var(--accent)}
.pwopts{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:6px}
.oi{display:flex;align-items:center;gap:7px}.oi label{color:var(--text2);font-size:12px;cursor:pointer}
.oi input[type=checkbox]{accent-color:var(--accent);width:14px;height:14px}
.oi input[type=number],.oi input[type=text]{width:60px;padding:3px 7px;background:var(--bg3);border:1px solid var(--border);border-radius:4px;color:var(--text);font-family:inherit;font-size:12px;outline:none}
/* DEVICE DETAIL TABS */
.dtabs{display:flex;gap:2px;border-bottom:1px solid var(--border);margin-bottom:16px}
.dtab{padding:7px 14px;border:none;background:transparent;color:var(--text2);font-family:inherit;font-size:11px;cursor:pointer;border-radius:6px 6px 0 0;border-bottom:2px solid transparent;margin-bottom:-1px;transition:all .18s;white-space:nowrap}
.dtab:hover{color:var(--text)}.dtab.act{color:var(--accent);border-bottom-color:var(--accent);background:rgba(0,212,170,.06)}
.dtab-pane{min-height:160px;animation:fi .15s}
/* INV DETAIL CARDS */
.inv-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:10px;margin-bottom:14px}
.icard{background:var(--bg3);border:1px solid var(--border);border-radius:var(--r);padding:13px}
.icard .il{font-size:10px;color:var(--text3);letter-spacing:1px;text-transform:uppercase;margin-bottom:4px}
.icard .iv{font-size:13px;font-weight:600;word-break:break-all}
.iv.ac{color:var(--accent)}.iv.bl{color:var(--accent2)}.iv.or{color:var(--accent3)}.iv.rd{color:var(--danger)}
/* HOSTNAME MISMATCH */
.hmm-banner{background:rgba(249,115,22,.1);border:1px solid rgba(249,115,22,.3);border-radius:var(--r);padding:7px 11px;font-size:11px;color:var(--accent3);margin-bottom:12px;display:flex;align-items:center;gap:8px}
/* STACK / NEIGHBOR ROWS */
.stack-row{background:var(--bg3);border:1px solid var(--border);border-radius:var(--r);padding:9px 12px;margin-bottom:6px;display:flex;align-items:center;gap:10px}
.nb-table{width:100%;border-collapse:collapse}
.nb-table th,.nb-table td{padding:7px 10px;text-align:left;border-bottom:1px solid var(--border);font-size:11px}
.nb-table th{color:var(--text2);font-size:10px;text-transform:uppercase;letter-spacing:.8px;font-weight:500}
.nb-table tr:last-child td{border-bottom:none}.nb-table tr:hover td{background:rgba(255,255,255,.015)}
/* BACKUP ROWS */
.bk-row{display:flex;align-items:center;gap:10px;padding:8px 12px;border-bottom:1px solid var(--border);transition:background .15s}
.bk-row:last-child{border-bottom:none}.bk-row:hover{background:rgba(255,255,255,.02)}.bk-row.clickable{cursor:pointer}
/* CONFIG VIEWER */
.conf-wrap{background:var(--bg);border:1px solid var(--border);border-radius:var(--r);overflow:auto;max-height:520px}
.conf-line{display:flex;gap:0}.conf-ln{color:var(--text3);min-width:44px;text-align:right;padding:0 8px 0 10px;flex-shrink:0;user-select:none;border-right:1px solid var(--border);font-size:10px;line-height:1.8}
.conf-txt{padding:0 10px;white-space:pre;font-size:11px;line-height:1.8;font-family:'JetBrains Mono',monospace}
.conf-line.hl{background:rgba(0,212,170,.08)}.conf-line.hl .conf-txt{color:var(--accent)}
/* DIFF VIEWER */
.diff-wrap{background:var(--bg);border:1px solid var(--border);border-radius:var(--r);overflow:auto;max-height:500px;font-family:'JetBrains Mono',monospace;font-size:11px;line-height:1.75}
.dl{padding:0 10px;white-space:pre}
.dl.add{background:rgba(34,197,94,.07);color:var(--ok)}.dl.rem{background:rgba(239,68,68,.07);color:var(--danger)}
.dl.hdr{background:rgba(59,130,246,.07);color:var(--accent2)}.dl.ctx{color:var(--text2)}
/* SCHEDULE */
.sch-row{display:grid;grid-template-columns:1fr 90px 70px 55px 50px;gap:8px;padding:8px 12px;border-bottom:1px solid var(--border);align-items:center;font-size:11px}
.sch-row:last-child{border-bottom:none}.sch-row:hover{background:rgba(255,255,255,.015)}
.sch-sel{background:var(--bg3);border:1px solid var(--border);border-radius:4px;color:var(--text);font-family:inherit;font-size:11px;padding:3px 6px;outline:none;width:100%}
.sch-sel:focus{border-color:var(--accent)}
/* DRILLDOWN */
.dditem{padding:7px 10px;cursor:pointer;border-radius:var(--r);display:flex;align-items:center;justify-content:space-between;transition:background .15s}
.dditem:hover{background:var(--bg3)}.dditem .ddc{color:var(--text2);font-size:11px}
.ddsub{padding-left:16px;border-left:2px solid var(--border);margin-left:10px;margin-top:2px}
/* EMPTY */
.empty{text-align:center;padding:40px;color:var(--text3)}.empty .ei{font-size:40px;opacity:.18;margin-bottom:10px}
/* DIFF SELECT */
.dsel-item{padding:6px 8px;border-radius:5px;cursor:pointer;font-size:11px;transition:all .15s;border:1px solid transparent}
.dsel-item:hover{background:var(--bg4)}.dsel-item.sel-a{border-color:var(--danger);background:rgba(239,68,68,.08)}
.dsel-item.sel-b{border-color:var(--ok);background:rgba(34,197,94,.08)}
.ssh-info{color:#58a6ff}.ssh-err{color:var(--danger)}
#ssh-terminal{user-select:text}
.inv-drop{position:absolute;top:calc(100% + 3px);left:0;min-width:220px;max-height:280px;overflow-y:auto;background:var(--bg2);border:1px solid var(--border);border-radius:var(--r);z-index:100;box-shadow:0 6px 24px rgba(0,0,0,.5)}
.inv-drop-srch{width:100%;box-sizing:border-box;padding:7px 10px;background:var(--bg3,var(--bg));border:none;border-bottom:1px solid var(--border);color:var(--text);font-size:12px;outline:none}
.inv-drop-item{padding:7px 12px;cursor:pointer;font-size:12px;display:flex;align-items:center;gap:8px;color:var(--text2);transition:background .1s}
.inv-drop-item:hover{background:var(--bg3,rgba(255,255,255,.05))}
.inv-drop-item.sel{color:var(--accent);font-weight:600}
.inv-drop-item .ck{width:14px;height:14px;border:1px solid var(--border);border-radius:3px;display:inline-flex;align-items:center;justify-content:center;font-size:10px;flex-shrink:0}
.inv-drop-item.sel .ck{background:var(--accent);border-color:var(--accent);color:#000}
</style>
</head>
<body>

<!-- ══════════ LOGIN ══════════ -->
<div id="login-screen">
  <div class="lbox">
    <div class="llogo"><span class="li">🐙</span><h1>OCTOPUS</h1><p>Network Management System</p></div>
    <div class="fg"><label>Kullanıcı Adı</label><input id="lu" type="text" placeholder="admin" autocomplete="username"></div>
    <div class="fg"><label>Şifre</label><input id="lp" type="password" placeholder="••••••••" autocomplete="current-password"></div>
    <button class="btn btn-p" id="lbtn" onclick="doLogin()"><span>Giriş Yap</span></button>
    <div class="errmsg" id="lerr"></div>
  </div>
</div>

<!-- ══════════ APP ══════════ -->
<div id="app">
  <div class="topbar">
    <div class="tlogo"><span class="ti">🐙</span>OCTOPUS</div>
    <nav class="tnav">
      <button class="nb act" onclick="gp('dashboard')" data-p="dashboard">⊞ Dashboard</button>
      <button class="nb adm" onclick="gp('vault')" data-p="vault" id="nb-vault">🔐 Passwords</button>
      <button class="nb" onclick="gp('inventory')" data-p="inventory">📋 Inventory</button>
      <button class="nb" onclick="gp('backup')" data-p="backup">💾 Backup</button>
      <button class="nb" onclick="gp('scan')" data-p="scan">🔍 Inventory Scan</button>
      <button class="nb" onclick="gp('collector')" data-p="collector">📦 Inventory Collector</button>
      <button class="nb" onclick="gp('schedule')" data-p="schedule">⏰ Backup Schedule</button>
      <button class="nb" onclick="gp('netmap')" data-p="netmap">🗺️ Network Map</button>
      <button class="nb" onclick="gp('ssh-logs')" data-p="ssh-logs">🖥️ SSH Session Logs</button>
      <button class="nb adm" onclick="gp('users')" data-p="users" id="nb-users">👥 Users</button>
    </nav>
    <div class="tuser">
      <div class="ubadge" onclick="toggleUDrop()">
        <span id="uname-badge">—</span><span style="color:var(--text3)">|</span><span class="role" id="urole-badge">—</span><span style="color:var(--text3);margin-left:2px">▾</span>
      </div>
    </div>
    <!-- User dropdown -->
    <div class="udrop" id="udrop">
      <div class="udrop-item" onclick="openChMyPw()">🔑 Şifre Değiştir</div>
      <div class="udrop-sep"></div>
      <div class="udrop-item" style="color:var(--danger)" onclick="doLogout()">🚪 Çıkış Yap</div>
    </div>
  </div>

  <div class="body">

    <!-- DASHBOARD -->
    <div class="pg act" id="pg-dashboard">
      <div class="sh"><div class="st">⊞ Dashboard</div>
        <button class="btn btn-s btn-sm" onclick="loadStats()">↻ Yenile</button></div>
      <div class="sgrid" id="sgrid"></div>
      <div class="ss">🧩 Modüller</div>
      <div class="mgrid" id="mgrid"></div>
    </div>

    <!-- VAULT -->
    <div class="pg" id="pg-vault">
      <div class="sh"><div class="st">🔐 Passwords</div>
        <div style="display:flex;gap:8px">
          <button class="btn btn-s btn-sm" onclick="openPwGen()">🎲 Şifre Üret</button>
          <button class="btn btn-p btn-sm" onclick="openAddVault()">+ Kayıt Ekle</button>
        </div></div>
      <div class="sbar"><input id="vsrch" placeholder="Servis ara…" oninput="renderVault()"></div>
      <div class="card" style="padding:0;overflow:hidden">
        <div class="tw"><table>
          <thead><tr><th>Servis</th><th>Alanlar</th><th style="width:100px">İşlem</th></tr></thead>
          <tbody id="vtb"></tbody>
        </table></div>
      </div>
    </div>

    <!-- INVENTORY -->
    <div class="pg" id="pg-inventory">
      <div class="sh"><div class="st">📋 Inventory</div>
        <div style="display:flex;gap:8px;align-items:center">
          <button class="btn btn-s btn-sm" onclick="gp('exclude')">🚫 Exclude</button>
          <button id="btn-status-check" class="btn btn-sm adm" style="background:rgba(34,197,94,.15);border:1px solid rgba(34,197,94,.4);color:#22c55e" onclick="runStatusCheck()" title="Filtre aktifse sadece görünen cihazları kontrol eder">🔄 Durum Kontrol</button>
          <div style="position:relative">
            <button class="btn btn-b btn-sm" onclick="toggleCsvMenu()">⬇️ Export CSV ▾</button>
            <div id="csv-menu" style="display:none;position:absolute;right:0;top:calc(100% + 4px);background:var(--bg2);border:1px solid var(--border);border-radius:var(--r);min-width:180px;z-index:50;box-shadow:0 4px 16px rgba(0,0,0,.4)">
              <div class="udrop-item" onclick="exportCsv('all')">📋 Tümünü Dışa Aktar</div>
              <div class="udrop-item" onclick="exportCsv('filtered')">🔍 Filtrelenenleri Aktar</div>
              <div id="csv-tag-items"></div>
            </div>
          </div>
          <button class="btn btn-p btn-sm adm" onclick="openAddInv(-1)">+ Cihaz Ekle</button>
        </div></div>
      <!-- Inventory Filtre Satırı -->
      <div id="inv-filter-bar" style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px;align-items:center">
        <input id="if-name" placeholder="🔤 Name…" oninput="renderInv()" style="width:140px;padding:6px 10px;background:var(--bg2);border:1px solid var(--border);border-radius:var(--r);color:var(--text);font-size:12px">
        <input id="if-ip"   placeholder="🌐 IP…"   oninput="renderInv()" style="width:120px;padding:6px 10px;background:var(--bg2);border:1px solid var(--border);border-radius:var(--r);color:var(--text);font-size:12px;font-family:monospace">
        <div style="position:relative">
          <button id="if-type-btn" onclick="openInvDropdown('type')" style="padding:6px 10px;background:var(--bg2);border:1px solid var(--border);border-radius:var(--r);color:var(--text);font-size:12px;cursor:pointer;min-width:130px;text-align:left;display:flex;justify-content:space-between;align-items:center;gap:6px">
            <span id="if-type-label">📦 Type…</span><span style="color:var(--text3);font-size:10px">▾</span>
          </button>
          <div id="if-type-drop" class="inv-drop" style="display:none"></div>
        </div>
        <div style="position:relative">
          <button id="if-cred-btn" onclick="openInvDropdown('cred')" style="padding:6px 10px;background:var(--bg2);border:1px solid var(--border);border-radius:var(--r);color:var(--text);font-size:12px;cursor:pointer;min-width:130px;text-align:left;display:flex;justify-content:space-between;align-items:center;gap:6px">
            <span id="if-cred-label">🔑 Credential…</span><span style="color:var(--text3);font-size:10px">▾</span>
          </button>
          <div id="if-cred-drop" class="inv-drop" style="display:none"></div>
        </div>
        <div style="position:relative">
          <button id="if-tag-btn" onclick="openInvDropdown('tag')" style="padding:6px 10px;background:var(--bg2);border:1px solid var(--border);border-radius:var(--r);color:var(--text);font-size:12px;cursor:pointer;min-width:120px;text-align:left;display:flex;justify-content:space-between;align-items:center;gap:6px">
            <span id="if-tag-label">🏷️ Tag…</span><span style="color:var(--text3);font-size:10px">▾</span>
          </button>
          <div id="if-tag-drop" class="inv-drop" style="display:none"></div>
        </div>
        <div style="position:relative">
          <button id="if-status-btn" onclick="toggleStatusDrop()" style="padding:6px 10px;background:var(--bg2);border:1px solid var(--border);border-radius:var(--r);color:var(--text);font-size:12px;cursor:pointer;min-width:120px;text-align:left;display:flex;justify-content:space-between;align-items:center;gap:6px">
            <span id="if-status-label">🔵 Durum…</span><span style="color:var(--text3);font-size:10px">▾</span>
          </button>
          <div id="if-status-drop" class="inv-drop" style="display:none;min-width:160px">
            <label style="display:flex;align-items:center;gap:6px;padding:6px 10px;cursor:pointer;font-size:12px"><input type="checkbox" value="green" onchange="onStatusFilter()"> <span style="width:10px;height:10px;border-radius:50%;background:#22c55e;display:inline-block"></span> Erişilebilir</label>
            <label style="display:flex;align-items:center;gap:6px;padding:6px 10px;cursor:pointer;font-size:12px"><input type="checkbox" value="orange" onchange="onStatusFilter()"> <span style="width:10px;height:10px;border-radius:50%;background:#f97316;display:inline-block"></span> Kısmi Erişim</label>
            <label style="display:flex;align-items:center;gap:6px;padding:6px 10px;cursor:pointer;font-size:12px"><input type="checkbox" value="red" onchange="onStatusFilter()"> <span style="width:10px;height:10px;border-radius:50%;background:#ef4444;display:inline-block"></span> Erişilemiyor</label>
            <label style="display:flex;align-items:center;gap:6px;padding:6px 10px;cursor:pointer;font-size:12px"><input type="checkbox" value="unknown" onchange="onStatusFilter()"> <span style="width:10px;height:10px;border-radius:50%;background:#6b7280;display:inline-block"></span> Kontrol Edilmedi</label>
          </div>
        </div>
        <button onclick="clearInvFilters()" id="if-clear-btn" style="display:none;padding:6px 10px;background:var(--danger);border:none;border-radius:var(--r);color:#fff;font-size:12px;cursor:pointer">✕ Temizle</button>
        <span id="if-count" style="font-size:11px;color:var(--text3);margin-left:4px"></span>
      </div>
      <div class="card" style="padding:0;overflow:hidden">
        <div class="tw"><table>
          <thead><tr id="inv-thead"><th style="width:60px;cursor:pointer" onclick="sortInv('status')" title="Duruma göre sırala">Durum <span id="srt-status"></span></th><th style="cursor:pointer" onclick="sortInv('name')" title="Ada göre sırala">Name <span id="srt-name">▲</span></th><th style="cursor:pointer" onclick="sortInv('ip')" title="IP'ye göre sırala">IP <span id="srt-ip"></span></th><th style="cursor:pointer" onclick="sortInv('device_type')" title="Tipe göre sırala">Type <span id="srt-device_type"></span></th><th style="cursor:pointer" onclick="sortInv('credential_id')" title="Credential'a göre sırala">Credential <span id="srt-credential_id"></span></th><th>Tags</th><th class="adm" style="width:90px">Actions</th></tr></thead>
          <tbody id="itb"></tbody>
        </table></div>
      </div>
    </div>

    <!-- EXCLUDE -->
    <div class="pg" id="pg-exclude">
      <div class="sh"><div class="st">🚫 Exclude</div>
        <div style="display:flex;gap:8px">
          <button class="btn btn-s btn-sm" onclick="gp('inventory')">← Geri</button>
          <button class="btn btn-p btn-sm adm" onclick="openAddExcl()">+ IP Ekle</button>
        </div></div>
      <div class="card" style="padding:0;overflow:hidden">
        <div class="tw"><table>
          <thead><tr><th>#</th><th>IP</th><th>Açıklama</th><th>Eklenme</th><th class="adm" style="width:70px">İşlem</th></tr></thead>
          <tbody id="etb"></tbody>
        </table></div>
      </div>
    </div>

    <!-- BACKUP -->
    <div class="pg" id="pg-backup">
      <div class="sh"><div class="st">💾 Network Backup</div><div style="display:flex;gap:8px;align-items:center"><button class="btn btn-s btn-sm" onclick="dlAllBackups()" title="Tüm backup dosyalarını ZIP olarak indir">⬇️ Tümünü İndir</button></div></div>
      <div class="g2">
        <div class="card cp">
          <div class="ct" style="margin-bottom:12px">🚀 Backup Başlat</div>
          <div class="fg"><label>Mod</label>
            <select id="bk-mode" onchange="toggleBkTag()">
              <option value="full">Full (tüm cihazlar)</option>
              <option value="tag">Tag'e Göre</option>
            </select></div>
          <div class="fg" id="bk-tag-row" style="display:none"><label>Tag</label>
            <input id="bk-tag" placeholder="cisco, firewall…"></div>
          <button class="btn btn-p" style="width:100%" onclick="startBackup()">▶ Başlat</button>
        </div>
        <div class="card cp">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
            <div class="ct">📟 Çıktı</div><div id="bk-badge"></div></div>
          <div class="logbox" id="bk-log"><div class="ll" style="color:var(--text3)">Backup başlatıldığında çıktı görünür…</div></div>
        </div>
      </div>
      <div class="ss">📁 Mevcut Backup'lar</div>
      <div id="bk-list"></div>
    </div>

    <!-- SCAN -->
    <div class="pg" id="pg-scan">
      <div class="sh"><div class="st">🔍 Inventory Scan</div></div>
      <div class="g2">
        <div class="card cp">
          <div class="ct" style="margin-bottom:12px">🎯 Hedef</div>
          <div class="fg"><label>IP / CIDR / Aralık</label>
            <input id="sc-tgt" placeholder="10.1.2.0/24 | 10.1.2.1-50 | 10.1.2.1"></div>
          <div style="font-size:11px;color:var(--text3);margin-bottom:10px">Maks 1024 IP.</div>
          <button class="btn btn-p" style="width:100%" onclick="startScan()">🔍 Tara</button>
        </div>
        <div class="card cp">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
            <div class="ct">📟 Çıktı</div><div id="sc-badge"></div></div>
          <div class="logbox" id="sc-log"><div class="ll" style="color:var(--text3)">Tarama başlatıldığında görünür…</div></div>
        </div>
      </div>
      <div id="sc-results"></div>
    </div>

    <!-- COLLECTOR -->
    <div class="pg" id="pg-collector">
      <div class="sh"><div class="st">📦 Inventory Collector</div></div>
      <div class="g2">
        <div class="card cp">
          <div class="ct" style="margin-bottom:12px">⚙️ Ayarlar</div>
          <div class="fg"><label>Tag Filtresi</label>
            <input id="col-tag" value="all" placeholder="all veya belirli tag"></div>
          <div style="font-size:11px;color:var(--text3);margin-bottom:10px">"all" tüm cihazları toplar.</div>
          <button class="btn btn-p" style="width:100%" onclick="startCollector()">▶ Başlat</button>
        </div>
        <div class="card cp">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
            <div class="ct">📟 Çıktı</div><div id="col-badge"></div></div>
          <div class="logbox" id="col-log"><div class="ll" style="color:var(--text3)">Toplayıcı başlatıldığında görünür…</div></div>
        </div>
      </div>
      <div class="ss">📄 Geçmiş Sonuçlar</div>
      <div id="col-outputs"></div>
    </div>

    <!-- SCHEDULE -->
    <div class="pg" id="pg-schedule">
      <div class="sh"><div class="st">⏰ Backup Schedule</div>
        <button class="btn btn-s btn-sm" onclick="loadSchedule()">↻ Yenile</button></div>
      <div class="card cp" style="margin-bottom:12px;font-size:11px;color:var(--text2)">
        ℹ️ Schedule tanımlı olmayan cihazlar <b style="color:var(--text)">her Pazar 00:00</b>'da otomatik yedeklenir.
        Değişiklikler anlık kaydedilir.
      </div>

      <div class="sbar"><input id="sch-srch" placeholder="Cihaz ara…" oninput="renderSchedule()"></div>
      <div class="card" style="padding:0;overflow:hidden">
        <div class="tw"><table id="sch-table">
          <thead><tr>
            <th>Cihaz</th><th>IP</th><th>Tip</th><th>Gün</th><th>Saat</th><th>Dak.</th><th>Aktif</th><th style="width:90px">İşlem</th>
          </tr></thead>
          <tbody id="sch-list"></tbody>
        </table></div>
      </div>
    </div>
    <!-- NETWORK MAP -->
    <div class="pg" id="pg-netmap">
      <div class="sh">
        <div class="st">🗺️ Network Map</div>
        <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
          <button class="btn btn-b btn-sm adm" id="btn-nmap-build" onclick="nmapBuild()">⚙️ Topoloji Oluştur</button>
          <button class="btn btn-s btn-sm" id="btn-nmap-export-csv" onclick="nmapExportCsv()" style="display:none">⬇️ CSV</button>
          <button class="btn btn-s btn-sm" id="btn-nmap-export-xml" onclick="nmapExportDrawio()" style="display:none">⬇️ Draw.io XML</button>
          <span id="nmap-status" style="font-size:12px;color:var(--text3)"></span>
        </div>
      </div>

      <!-- Filtre & Özet -->
      <div style="display:flex;gap:8px;margin-bottom:10px;flex-wrap:wrap;align-items:center">
        <input id="nmap-filter" type="text" placeholder="Cihaz veya VLAN ara…"
          style="padding:6px 10px;background:var(--bg2);border:1px solid var(--border);
                 border-radius:var(--r);color:var(--text);font-size:12px;min-width:200px"
          oninput="nmapRender()">
        <span id="nmap-count" style="font-size:11px;color:var(--text3)"></span>
      </div>

      <!-- Progress bar -->
      <div id="nmap-progress" style="display:none;margin-bottom:10px">
        <div style="background:var(--bg2);border-radius:4px;height:8px;overflow:hidden">
          <div id="nmap-pbar" style="height:100%;background:var(--accent);width:0%;transition:width .3s"></div>
        </div>
        <div id="nmap-prog-msg" style="font-size:11px;color:var(--text3);margin-top:4px"></div>
      </div>

      <!-- Bağlantı tablosu -->
      <div class="card" style="padding:0;overflow:hidden">
        <div class="tw"><table id="nmap-table">
          <thead><tr>
            <th>Lokal Cihaz</th>
            <th>Lokal Port</th>
            <th>Uzak Cihaz</th>
            <th>Uzak Port</th>
            <th>Lokal PO</th>
            <th>Lokal PO Üyeler</th>
            <th>Lokal VLAN</th>
            <th>Uzak PO</th>
            <th>Uzak VLAN</th>
            <th>Aktif VLAN</th>
            <th>Prot.</th>
            <th>Durum</th>
          </tr></thead>
          <tbody id="nmap-tbody"></tbody>
        </table></div>
      </div>
    </div>

<!-- SSH LOGS -->
    <div class="pg" id="pg-ssh-logs">
      <div class="sh"><div class="st">🖥️ SSH Session Logs</div>
        <button class="btn btn-s btn-sm" onclick="loadSshLogs()">↻ Yenile</button></div>
      <div class="card cp" style="margin-bottom:12px;font-size:11px;color:var(--text2)">
        SSH oturumları otomatik kaydedilir. Dosyalar sunucuda <code>app/ssh_logs/</code> klasöründe tutulur.
      </div>
      <div class="card" style="padding:0;overflow:hidden">
        <div id="ssh-logs-list" style="min-height:80px;padding:0">
          <div class="empty"><div class="ei">📋</div><p>Yükleniyor…</p></div>
        </div>
      </div>
    </div>

    <!-- USERS -->
    <div class="pg" id="pg-users">
      <div class="sh"><div class="st">👥 Users</div>
        <button class="btn btn-p btn-sm" onclick="openAddUser()">+ Kullanıcı Ekle</button></div>
      <div class="card" style="padding:0;overflow:hidden">
        <div class="tw"><table>
          <thead><tr><th>Kullanıcı</th><th>Rol</th><th style="width:160px">İşlem</th></tr></thead>
          <tbody id="utb"></tbody>
        </table></div>
      </div>
    </div>

  </div><!-- /body -->
</div><!-- /app -->

<div class="toasts" id="toasts"></div>

<!-- ════════════════ MODALS ════════════════ -->

<!-- Vault Add/Edit -->
<div class="overlay" id="mv"><div class="modal wide">
  <button class="mc" onclick="cm('mv')">✕</button>
  <div class="mt">🔐 <span id="mv-t">Vault Kaydı</span></div>
  <input type="hidden" id="mv-orig">
  <div class="fg"><label>Servis Adı</label><input id="mv-svc" placeholder="örn: sw_creds"></div>
  <div style="color:var(--text2);font-size:10px;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">Alanlar</div>
  <div id="mv-fields"></div>
  <div style="display:flex;gap:8px;margin-bottom:4px">
    <input id="mv-nk" placeholder="Alan adı" style="flex:1;padding:7px 10px;background:var(--bg3);border:1px solid var(--border);border-radius:var(--r);color:var(--text);font-family:inherit;font-size:12px;outline:none">
    <input id="mv-nv" placeholder="Değer" style="flex:2;padding:7px 10px;background:var(--bg3);border:1px solid var(--border);border-radius:var(--r);color:var(--text);font-family:inherit;font-size:12px;outline:none">
    <button class="btn btn-s btn-sm" onclick="addMvF()">+ Alan</button>
  </div>
  <div class="mf"><button class="btn btn-s" onclick="cm('mv')">İptal</button><button class="btn btn-p" onclick="saveVault()">💾 Kaydet</button></div>
</div></div>

<!-- Vault Detail -->
<div class="overlay" id="mvd"><div class="modal wide">
  <button class="mc" onclick="cm('mvd')">✕</button>
  <div class="mt">🔑 <span id="mvd-t"></span></div>
  <div id="mvd-body"></div>
  <div class="mf"><button class="btn btn-s" onclick="cm('mvd')">Kapat</button></div>
</div></div>

<!-- Pw Gen -->
<div class="overlay" id="mpw"><div class="modal">
  <button class="mc" onclick="cm('mpw')">✕</button>
  <div class="mt">🎲 Şifre Üreteci</div>
  <div class="pwd"><span class="pwtxt" id="pw-val">—</span><button class="btn btn-s btn-sm" onclick="cpPw()">📋</button></div>
  <div class="pwopts">
    <div class="oi"><label>Uzunluk</label><input type="number" id="pg-len" value="16" min="6" max="64"></div>
    <div class="oi"><input type="checkbox" id="pg-u" checked><label for="pg-u">Büyük harf</label></div>
    <div class="oi"><input type="checkbox" id="pg-l" checked><label for="pg-l">Küçük harf</label></div>
    <div class="oi"><input type="checkbox" id="pg-d" checked><label for="pg-d">Rakam</label></div>
    <div class="oi"><input type="checkbox" id="pg-s" checked><label for="pg-s">Özel</label></div>
    <div class="oi"><label>Özel karakterler</label><input type="text" id="pg-sc" value="%!.*@"></div>
  </div>
  <div class="mf"><button class="btn btn-s" onclick="cm('mpw')">Kapat</button><button class="btn btn-p" onclick="genPw()">🔄 Üret</button></div>
</div></div>

<!-- Inventory Add/Edit -->
<div class="overlay" id="mi"><div class="modal">
  <button class="mc" onclick="cm('mi')">✕</button>
  <div class="mt">🖧 <span id="mi-t">Cihaz</span></div>
  <input type="hidden" id="mi-idx" value="-1">
  <div class="fg"><label>Cihaz Adı</label><input id="mi-name" placeholder="CORE_SW1"></div>
  <div class="g2">
    <div class="fg"><label>IP Adresi</label><input id="mi-ip" placeholder="10.0.0.1"></div>
    <div class="fg"><label>Port</label><input type="number" id="mi-port" placeholder="22/443"></div>
  </div>
  <div class="fg"><label>Cihaz Tipi</label>
    <select id="mi-type">
      <option>cisco_ios</option><option>cisco_nxos</option><option>cisco_ap</option><option>huawei</option>
      <option>dell_force10</option><option>hp_comware</option><option>hp_procurve</option><option>h3c_comware</option>
      <option>extreme_exos</option><option>ruijie_os</option>
      <option>fortigate</option><option>fortianalyzer</option><option>fortimanager</option>
      <option>fortiauthenticator</option><option>fortisandbox</option>
      <option>bigip</option><option>velos_sc</option><option>velos_partition</option><option>unknown</option>
    </select></div>
  <div class="fg"><label>Credential ID</label><input id="mi-cred" placeholder="sw_creds"></div>
  <div class="g2">
    <div class="fg"><label>MAC Adresi</label><input id="mi-mac" placeholder="aa:bb:cc:dd:ee:ff" style="font-family:monospace"></div>
    <div class="fg"><label>Serial No</label><input id="mi-serial" placeholder="ABC123DEF456" style="font-family:monospace"></div>
  </div>
  <div class="fg"><label>Tags (virgülle)</label><input id="mi-tags" placeholder="all, cisco, dc1"></div>
  <div class="mf"><button class="btn btn-s" onclick="cm('mi')">İptal</button><button class="btn btn-p" onclick="saveInv()">💾 Kaydet</button></div>
</div></div>

<!-- Device Detail -->
<div class="overlay" id="mid"><div class="modal xl">
  <button class="mc" onclick="cm('mid')">✕</button>
  <!-- Header -->
  <div style="display:flex;align-items:flex-start;gap:10px;margin-bottom:14px;flex-wrap:wrap">
    <div style="flex:1;min-width:0">
      <div style="font-family:'Syne',sans-serif;font-size:17px;font-weight:700;display:flex;align-items:center;gap:8px;flex-wrap:wrap">
        🖧 <span id="mid-name">—</span>
        <code id="mid-ip" style="font-size:12px;color:var(--accent2);font-weight:400"></code>
      </div>
      <div id="mid-mac-sn" style="margin-top:4px"></div>
      <div id="mid-hmm"></div>
    </div>
    <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;flex-shrink:0">
      <div id="mid-cbadge"></div>
      <button class="btn btn-o btn-sm" id="mid-col-btn" onclick="collectSingle()">⚡ Envanter Al</button>
      <button class="btn btn-p btn-sm" id="mid-bk-btn" onclick="backupSingle()">💾 Backup Al</button>
      <button class="btn btn-b btn-sm" id="mid-nb-btn" onclick="collectNeighbors()">🔗 Komşuluk</button>
      <button class="btn btn-sm" id="mid-status-btn" style="background:rgba(34,197,94,.15);border:1px solid rgba(34,197,94,.4);color:#22c55e" onclick="runStatusCheckSingle(_iD[_curDevIdx]?.ip)">🔍 Durum Kontrol</button>
      <button class="btn btn-s btn-sm adm" id="mid-edit-btn">✏️ Düzenle</button>
    </div>
  </div>
  <!-- Tabs -->
  <div class="dtabs">
    <button class="dtab act" onclick="swDTab('info')" data-dt="info">📋 Genel</button>
    <button class="dtab" onclick="swDTab('hw')" data-dt="hw">🔧 Envanter</button>
    <button class="dtab" onclick="swDTab('nb')" data-dt="nb">🔗 Komşular<span id="nb-cnt" style="margin-left:5px"></span></button>
    <button class="dtab" onclick="swDTab('bk')" data-dt="bk">💾 Backup<span id="bk-cnt" style="margin-left:5px"></span></button>
    <button class="dtab" onclick="swDTab('ssh')" data-dt="ssh" id="ssh-tab-btn">🖥️ SSH</button>
  </div>
  <div id="dtab-info" class="dtab-pane"></div>
  <div id="dtab-hw"   class="dtab-pane" style="display:none"></div>
  <div id="dtab-nb"   class="dtab-pane" style="display:none"></div>
  <div id="dtab-bk"   class="dtab-pane" style="display:none"></div>
  <div id="dtab-ssh"  class="dtab-pane" style="display:none">
    <div id="ssh-toolbar" style="display:flex;align-items:center;gap:8px;margin-bottom:8px;flex-wrap:wrap">
      <button class="btn btn-p btn-sm" id="ssh-conn-btn" onclick="sshConnect()">⚡ Bağlan</button>
      <button class="btn btn-s btn-sm" id="ssh-disc-btn" onclick="sshDisconnect()" style="display:none">🔌 Kes</button>
      <span id="ssh-status" style="font-size:11px;color:var(--text2)">Bağlı değil</span>
      <div style="margin-left:auto;display:flex;gap:6px">
        <button class="btn btn-b btn-sm" id="ssh-log-dl-btn" style="display:none" onclick="sshDownloadLog()">⬇️ Log İndir</button>
        <button class="btn btn-s btn-sm" onclick="goSshLogs()">📋 Kayıtlar</button>
      </div>
    </div>
    <div id="ssh-terminal" style="background:#0d1117;border-radius:var(--r);padding:10px 12px;font-family:'Courier New',monospace;font-size:12px;line-height:1.45;height:420px;overflow:hidden;position:relative;cursor:text" onclick="document.getElementById('ssh-input-trap').focus()">
      <div id="ssh-output" style="height:100%;overflow-y:auto;white-space:pre-wrap;word-break:break-all;color:#e6edf3"></div>
      <input id="ssh-input-trap" style="position:absolute;opacity:0;width:1px;height:1px;left:-9999px"
        onkeydown="sshKeyDown(event)" oninput="sshInput(event)">
    </div>
  </div>
  <div class="mf"><button class="btn btn-s" onclick="cm('mid')">Kapat</button></div>
</div></div>

<!-- Config Viewer -->
<div class="overlay" id="mcv"><div class="modal xl">
  <button class="mc" onclick="cm('mcv')">✕</button>
  <div class="mt">📄 <span id="mcv-title">Konfig</span></div>
  <div style="display:flex;gap:8px;align-items:center;margin-bottom:10px">
    <input id="mcv-srch" placeholder="Satır ara…" style="flex:1;padding:7px 11px;background:var(--bg3);border:1px solid var(--border);border-radius:var(--r);color:var(--text);font-family:inherit;font-size:12px;outline:none" oninput="confSearch()">
    <span id="mcv-info" style="color:var(--text2);font-size:11px;white-space:nowrap"></span>
    <button id="mcv-dl-btn" class="btn btn-b btn-xs" style="display:none;margin-left:4px">⬇️ İndir</button>
  </div>
  <div class="conf-wrap" id="mcv-body"></div>
  <div class="mf"><button class="btn btn-s" onclick="cm('mcv')">Kapat</button></div>
</div></div>

<!-- Diff Select -->
<div class="overlay" id="mds"><div class="modal wide">
  <button class="mc" onclick="cm('mds')">✕</button>
  <div class="mt">🔀 Backup Karşılaştırma</div>
  <div style="font-size:11px;color:var(--text2);margin-bottom:10px">Karşılaştırmak istediğiniz <b>iki</b> dosyayı seçin. A=eski, B=yeni.</div>
  <div class="g2">
    <div>
      <div style="font-size:10px;color:var(--danger);text-transform:uppercase;letter-spacing:1px;margin-bottom:6px;font-weight:600">A — Eski</div>
      <div id="ds-list-a" style="background:var(--bg3);border:1px solid var(--border);border-radius:var(--r);max-height:260px;overflow-y:auto;padding:4px"></div>
    </div>
    <div>
      <div style="font-size:10px;color:var(--ok);text-transform:uppercase;letter-spacing:1px;margin-bottom:6px;font-weight:600">B — Yeni</div>
      <div id="ds-list-b" style="background:var(--bg3);border:1px solid var(--border);border-radius:var(--r);max-height:260px;overflow-y:auto;padding:4px"></div>
    </div>
  </div>
  <div style="font-size:11px;color:var(--text2);margin-bottom:8px">
    A: <b id="ds-a-name" style="color:var(--text)">—</b> &nbsp; B: <b id="ds-b-name" style="color:var(--text)">—</b>
  </div>
  <div class="mf"><button class="btn btn-s" onclick="cm('mds')">İptal</button><button class="btn btn-p" id="ds-go" onclick="runDiff()" disabled>🔀 Karşılaştır</button></div>
</div></div>

<!-- Diff Viewer -->
<div class="overlay" id="mdv"><div class="modal xl">
  <button class="mc" onclick="cm('mdv')">✕</button>
  <div class="mt">🔀 Fark Görüntüleyici</div>
  <div style="display:flex;gap:8px;margin-bottom:10px;font-size:11px;align-items:center">
    <div style="flex:1;background:var(--bg3);border:1px solid var(--border);border-radius:var(--r);padding:6px 10px">
      <span style="color:var(--danger);font-weight:600">A: </span><span id="dv-a-name">—</span></div>
    <div style="flex:1;background:var(--bg3);border:1px solid var(--border);border-radius:var(--r);padding:6px 10px">
      <span style="color:var(--ok);font-weight:600">B: </span><span id="dv-b-name">—</span></div>
    <div id="dv-summary"></div>
  </div>
  <div class="diff-wrap" id="dv-body"></div>
  <div class="mf"><button class="btn btn-s" onclick="cm('mdv')">Kapat</button></div>
</div></div>

<!-- Stats Drilldown -->
<div class="overlay" id="mdd"><div class="modal wide">
  <button class="mc" onclick="cm('mdd')">✕</button>
  <div class="mt"><span id="mdd-t">Detay</span></div>
  <div id="mdd-body" style="max-height:560px;overflow-y:auto"></div>
  <div class="mf"><button class="btn btn-s" onclick="cm('mdd')">Kapat</button></div>
</div></div>

<!-- Add Exclude -->
<div class="overlay" id="mae"><div class="modal" style="width:360px">
  <button class="mc" onclick="cm('mae')">✕</button>
  <div class="mt">🚫 Exclude IP</div>
  <div class="fg"><label>IP</label><input id="ae-ip" placeholder="10.0.0.1"></div>
  <div class="fg"><label>Açıklama (opsiyonel)</label><input id="ae-desc"></div>
  <div class="mf"><button class="btn btn-s" onclick="cm('mae')">İptal</button><button class="btn btn-p" onclick="addExclude()">Ekle</button></div>
</div></div>

<!-- Add User -->
<div class="overlay" id="mau"><div class="modal" style="width:360px">
  <button class="mc" onclick="cm('mau')">✕</button>
  <div class="mt">👤 Kullanıcı Ekle</div>
  <div class="fg"><label>Kullanıcı Adı</label><input id="au-n"></div>
  <div class="fg"><label>Şifre</label><input type="password" id="au-p"></div>
  <div class="fg"><label>Rol</label>
    <select id="au-r"><option value="user">Kullanıcı</option><option value="admin">Admin</option></select></div>
  <div class="mf"><button class="btn btn-s" onclick="cm('mau')">İptal</button><button class="btn btn-p" onclick="addUser()">Ekle</button></div>
</div></div>

<!-- Admin Change User Pw -->
<div class="overlay" id="mcp"><div class="modal" style="width:340px">
  <button class="mc" onclick="cm('mcp')">✕</button>
  <div class="mt">🔑 Şifre Değiştir — <span id="cp-name" style="color:var(--accent2)"></span></div>
  <input type="hidden" id="cp-u">
  <div class="fg"><label>Yeni Şifre</label><input type="password" id="cp-p"></div>
  <div class="mf"><button class="btn btn-s" onclick="cm('mcp')">İptal</button><button class="btn btn-p" onclick="changeUserPw()">Kaydet</button></div>
</div></div>

<!-- My Password Change -->
<div class="overlay" id="mmpc"><div class="modal" style="width:360px">
  <button class="mc" onclick="cm('mmpc')">✕</button>
  <div class="mt">🔑 Şifremi Değiştir</div>
  <div id="mmpc-admin-note" style="display:none;background:rgba(249,115,22,.1);border:1px solid rgba(249,115,22,.3);border-radius:var(--r);padding:8px 11px;font-size:11px;color:var(--accent3);margin-bottom:12px">
    ⚠️ Admin şifresi vault master key'dir. Vault şifresini değiştirerek güncellenebilir.
  </div>
  <div id="mmpc-form">
    <div class="fg"><label>Mevcut Şifre</label><input type="password" id="mpc-old"></div>
    <div class="fg"><label>Yeni Şifre</label><input type="password" id="mpc-new"></div>
    <div class="fg"><label>Yeni Şifre (Tekrar)</label><input type="password" id="mpc-new2"></div>
    <div class="mf"><button class="btn btn-s" onclick="cm('mmpc')">İptal</button><button class="btn btn-p" onclick="doMyPwChange()">Kaydet</button></div>
  </div>
</div></div>

<!-- Collector Result Viewer -->
<div class="overlay" id="mcr"><div class="modal wide">
  <button class="mc" onclick="cm('mcr')">✕</button>
  <div class="mt">📄 <span id="mcr-t">Sonuç</span></div>
  <div id="mcr-body" style="max-height:500px;overflow-y:auto"></div>
  <div class="mf"><button class="btn btn-s" onclick="cm('mcr')">Kapat</button></div>
</div></div>

<script>
// ════════════════════════════════════════════════════
// STATE
// ════════════════════════════════════════════════════
let _role=null, _username=null;
let _vD={}, _iD=[], _eD=[], _schD={}, _iS={};
let _mvFields={};          // vault modal fields
let _curDevIdx=-1;         // active device in detail modal
let _devBkFiles=[];        // backup files for current device (diff)
let _dsSelA=null,_dsSelB=null;

// ════════════════════════════════════════════════════
// CORE HELPERS
// ════════════════════════════════════════════════════
function esc(s){return String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function enc(s){return encodeURIComponent(String(s??''));}
function fmtSz(b){if(b<1024)return b+' B';if(b<1048576)return (b/1024).toFixed(1)+' KB';return (b/1048576).toFixed(1)+' MB';}
function om(id){document.getElementById(id).classList.add('open');}
function cm(id){
  document.getElementById(id)?.classList.remove('open');
  if(id==='mid') sshDisconnect();
}
function toast(m,t='info',d=3200){
  const c=document.getElementById('toasts'),el=document.createElement('div');
  el.className=`toast ${t}`;el.textContent=m;c.appendChild(el);
  setTimeout(()=>{el.style.transition='opacity .3s';el.style.opacity='0';},d-300);
  setTimeout(()=>el.remove(),d);
}

// ── Push Notification (SSE) ──────────────────────────────
let _notifEvt = null;

function _startNotifStream(){
  if(_notifEvt) return;
  // Sadece giriş yapılmışsa bağlan
  if(!_role) return;
  _notifEvt = new EventSource('/api/notifications/stream');
  _notifEvt.onmessage = (ev) => {
    if(!ev.data || ev.data === '{}') return; // heartbeat
    let msg;
    try { msg = JSON.parse(ev.data); } catch(_){ return; }
    if(!msg.message) return;
    _showPushNotification(msg.message, msg.type || 'ok', msg.ts || '');
  };
  _notifEvt.onerror = () => {
    _notifEvt?.close(); _notifEvt = null;
    // Sadece giriş yapılmışsa yeniden bağlan
    if(_role) setTimeout(_startNotifStream, 3000);
  };
}

function _showPushNotification(message, type, ts){
  // Create a prominent banner at top-center of screen
  const existing = document.getElementById('push-notif-banner');
  if(existing) existing.remove();

  const banner = document.createElement('div');
  banner.id = 'push-notif-banner';
  const icon = type==='ok' ? '✅' : type==='err' ? '❌' : 'ℹ️';
  const borderColor = type==='ok' ? 'var(--ok)' : type==='err' ? 'var(--danger)' : 'var(--accent2)';
  banner.style.cssText = [
    'position:fixed','top:20px','left:50%','transform:translateX(-50%) translateY(-80px)',
    'z-index:500','background:var(--bg2)','border:1px solid '+borderColor,
    'border-top:3px solid '+borderColor,'border-radius:var(--r2)',
    'padding:14px 22px','display:flex','align-items:center','gap:12px',
    'box-shadow:0 8px 40px rgba(0,0,0,.6)','min-width:320px','max-width:520px',
    'transition:transform .4s cubic-bezier(.175,.885,.32,1.275)',
    'cursor:pointer'
  ].join(';');

  banner.innerHTML = `
    <span style="font-size:22px;flex-shrink:0">${icon}</span>
    <div style="flex:1;min-width:0">
      <div style="font-weight:600;font-size:13px;color:var(--text)">${esc(message)}</div>
      ${ts ? `<div style="font-size:10px;color:var(--text3);margin-top:2px">🕐 ${esc(ts)}</div>` : ''}
    </div>
    <button onclick="this.parentElement.remove()" style="background:none;border:none;color:var(--text3);font-size:18px;cursor:pointer;padding:0 0 0 8px;flex-shrink:0;line-height:1">✕</button>`;

  banner.onclick = (e) => { if(e.target.tagName!=='BUTTON') banner.remove(); };
  document.body.appendChild(banner);

  // Slide in
  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      banner.style.transform = 'translateX(-50%) translateY(0)';
    });
  });

  // Also show as toast for good measure
  toast(message, type, 5000);

  // Auto-dismiss after 8s
  setTimeout(() => {
    banner.style.transition = 'opacity .5s, transform .5s';
    banner.style.opacity = '0';
    banner.style.transform = 'translateX(-50%) translateY(-20px)';
    setTimeout(() => banner.remove(), 500);
  }, 8000);
}
async function api(method,url,body){
  const opts={method,headers:{'Content-Type':'application/json'}};
  if(body)opts.body=JSON.stringify(body);
  const r=await fetch(url,opts);
  const j=await r.json();
  if(!r.ok)throw new Error(j.error||`HTTP ${r.status}`);
  return j;
}
function setBadge(id,state){
  const el=document.getElementById(id);if(!el)return;
  el.innerHTML={running:'<span class="tag tb">⏳ Çalışıyor</span>',done:'<span class="tag tg">✅ Tamamlandı</span>',error:'<span class="tag tr">❌ Hata</span>'}[state]||'';
}
function pollJob(jid,logElId,badgeId,onDone){
  let last=0;
  const iv=setInterval(async()=>{
    try{
      const j=await api('GET',`/api/job/${jid}`);
      if(logElId){
        const log=document.getElementById(logElId);
        if(log){
          j.log.slice(last).forEach(l=>{
            const d=document.createElement('div');
            const c=l.includes('✅')||l.includes('[OK]')||l.includes('Başarılı')?' ok':l.includes('❌')||l.includes('[HATA')||l.includes('Başarısız')?' err':l.includes('───')?' hdr':'';
            d.className='ll'+c;d.textContent=l;log.appendChild(d);log.scrollTop=log.scrollHeight;
          });
        }
      }
      last=j.log.length;
      if(j.status==='done'){clearInterval(iv);setBadge(badgeId,'done');if(onDone)onDone(j);}
      else if(j.status==='error'){clearInterval(iv);setBadge(badgeId,'error');toast('İş başarısız: '+(j.error||'?'),'err');}
    }catch(e){clearInterval(iv);}
  },1000);
}

// ════════════════════════════════════════════════════
// LOGIN
// ════════════════════════════════════════════════════
async function doLogin(){
  const u=document.getElementById('lu').value.trim(),p=document.getElementById('lp').value;
  const err=document.getElementById('lerr'),btn=document.getElementById('lbtn');
  err.textContent='';if(!u||!p){err.textContent='Kullanıcı adı ve şifre gerekli.';return;}
  btn.disabled=true;btn.querySelector('span').textContent='Giriş yapılıyor…';
  try{const r=await api('POST','/api/login',{username:u,password:p});_role=r.role;_username=r.username;initApp();}
  catch(e){err.textContent=e.message||'Giriş başarısız.';}
  finally{btn.disabled=false;btn.querySelector('span').textContent='Giriş Yap';}
}
document.addEventListener('keydown',e=>{
  if(e.key==='Enter'&&!document.getElementById('login-screen').style.display)doLogin();
});
async function doLogout(){await fetch('/logout');location.reload();}

// User dropdown
function toggleUDrop(){document.getElementById('udrop').classList.toggle('open');}
document.addEventListener('click',e=>{if(!e.target.closest('.tuser')&&!e.target.closest('.udrop'))document.getElementById('udrop').classList.remove('open');});

// My password change
function openChMyPw(){
  document.getElementById('udrop').classList.remove('open');
  const isAdmin=_role==='admin';
  document.getElementById('mmpc-admin-note').style.display=isAdmin?'block':'none';
  document.getElementById('mmpc-form').style.display=isAdmin?'none':'block';
  document.getElementById('mpc-old').value='';document.getElementById('mpc-new').value='';document.getElementById('mpc-new2').value='';
  om('mmpc');
}
async function doMyPwChange(){
  const old=document.getElementById('mpc-old').value,nw=document.getElementById('mpc-new').value,nw2=document.getElementById('mpc-new2').value;
  if(!old||!nw){toast('Tüm alanlar zorunlu','err');return;}
  if(nw!==nw2){toast('Yeni şifreler eşleşmiyor','err');return;}
  if(nw.length<6){toast('En az 6 karakter gerekli','err');return;}
  try{await api('PUT','/api/profile/password',{old_password:old,new_password:nw});toast('Şifre değiştirildi','ok');cm('mmpc');}
  catch(e){toast(e.message,'err');}
}

// ════════════════════════════════════════════════════
// INIT
// ════════════════════════════════════════════════════
function initApp(){
  document.getElementById('login-screen').style.display='none';
  document.getElementById('app').classList.add('v');
  document.getElementById('uname-badge').textContent=_username;
  document.getElementById('urole-badge').textContent=_role==='admin'?'Admin':'Kullanıcı';
  // admin-only elements
  document.querySelectorAll('.adm').forEach(el=>{
    el.style.display=_role==='admin'?'':'none';
  });
  // Push notification stream
  _startNotifStream();
  loadStats();buildModuleGrid();
}
function gp(name){
  document.querySelectorAll('.pg').forEach(p=>p.classList.remove('act'));
  document.querySelectorAll('.nb').forEach(b=>b.classList.remove('act'));
  const pg=document.getElementById('pg-'+name);if(pg)pg.classList.add('act');
  const nb=document.querySelector(`.nb[data-p="${name}"]`);if(nb)nb.classList.add('act');
  ({
    vault:()=>{if(_role==='admin')loadVault();},
    inventory:loadInventory,
    exclude:loadExclude,
    backup:loadBackups,
    collector:loadColOutputs,
    schedule:()=>{if(!_iD.length)loadInventory().then(loadSchedule);else loadSchedule();},
    'ssh-logs':loadSshLogs,
    netmap:nmapLoad,
    users:()=>{if(_role==='admin')loadUsers();},
  }[name]||(() => {}))();
}

// ════════════════════════════════════════════════════
// DASHBOARD
// ════════════════════════════════════════════════════
async function loadStats(){
  try{
    const s=await api('GET','/api/stats');
    const cards=[
      {c:'g',i:'🔑',v:s.vault,l:'Vault Kaydı',t:'vault',adm:true},
      {c:'b',i:'🖧',v:s.inventory,l:'Cihaz',t:'inventory',adm:false},
      {c:'o',i:'👥',v:s.users,l:'Kullanıcı',t:'users',adm:true},
      {c:'r',i:'🚫',v:s.exclude,l:'Exclude IP',t:'exclude',adm:false},
      {c:'gr',i:'💾',v:s.backup_files,l:`Backup (${s.backup_days} gün)`,t:'backups',adm:false},
    ].filter(x=>!x.adm||_role==='admin');
    document.getElementById('sgrid').innerHTML=cards.map(c=>`
      <div class="sc ${c.c}" onclick="openDrilldown('${c.t}')">
        <div class="sv">${c.v}</div><div class="sl">${c.l}</div><div class="sic">${c.i}</div>
      </div>`).join('');
  }catch(e){toast('İstatistikler yüklenemedi','err');}
}
function buildModuleGrid(){
  const mods=[
    {i:'💾',n:'Network Backup',d:'Cihaz konfigürasyonlarını yedekler.',p:'backup'},
    {i:'🔍',n:'Inventory Scan',d:'Ağı tarayarak yeni cihazları keşfeder.',p:'scan'},
    {i:'📦',n:'Inventory Collector',d:'Donanım/yazılım envanteri toplar.',p:'collector'},
    {i:'⏰',n:'Backup Schedule',d:'Otomatik yedekleme zamanlaması.',p:'schedule'},
    {i:'📋',n:'Inventory',d:'Cihaz listesi ve detayları.',p:'inventory'},
  ];
  if(_role==='admin')mods.unshift({i:'🔐',n:'Vault',d:'Şifreli credential yönetimi.',p:'vault'});
  document.getElementById('mgrid').innerHTML=mods.map(m=>`
    <div class="mcard" onclick="gp('${m.p}')">
      <div class="mico">${m.i}</div><div class="mname">${m.n}</div><div class="mdesc">${m.d}</div><div class="mArr">›</div>
    </div>`).join('');
}

// Stats Drilldown
async function openDrilldown(type){
  if(type==='vault'){gp('vault');return;}
  if(type==='exclude'){gp('exclude');return;}
  const titles={inventory:'📋 Inventory Özeti',users:'👥 Kullanıcılar',backups:'💾 Backuplar'};
  document.getElementById('mdd-t').textContent=titles[type]||type;
  const body=document.getElementById('mdd-body');
  body.innerHTML='<div class="empty"><div class="ei">⏳</div><p>Yükleniyor…</p></div>';
  om('mdd');
  try{
    const d=await api('GET',`/api/stats/detail/${type}`);
    if(type==='users') renderDDUsers(body,d);
    else if(type==='inventory') renderDDInventory(body,d);
    else if(type==='backups') renderDDBackups(body,d);
  }catch(e){body.innerHTML=`<p style="color:var(--danger);padding:14px">${esc(e.message)}</p>`;}
}
function renderDDUsers(body,data){
  body.innerHTML=`<div class="card" style="padding:0;overflow:hidden"><div class="tw"><table>
    <thead><tr><th>Kullanıcı</th><th>Rol</th></tr></thead>
    <tbody>${data.map(u=>`<tr><td><b>${esc(u.username)}</b>${u.system?` <span class="tag to" style="margin-left:6px">sistem</span>`:''}</td>
      <td><span class="tag ${u.role==='admin'?'to':'tb'}">${u.role}</span></td></tr>`).join('')}</tbody>
  </table></div></div>`;
}
function renderDDInventory(body,d){
  // Marka/tip ağaç yapısı
  let brandHtml='';
  Object.entries(d.by_brand).sort((a,b)=>{
    const ta=Object.values(a[1]).flat().length,tb2=Object.values(b[1]).flat().length;return tb2-ta;
  }).forEach(([brand,types])=>{
    const total=Object.values(types).flat().length;
    const subId='dd-'+brand.replace(/\W/g,'_');
    brandHtml+=`<div class="dditem" onclick="toggleDD('${subId}')">
      <span style="display:flex;align-items:center;gap:7px">
        <span style="font-size:14px">${brand==='Cisco'?'🔵':brand==='Huawei'?'🟠':brand==='Fortinet'?'🔴':brand==='F5'?'🟣':brand==='H3C'?'🟡':brand==='Extreme Networks'?'🟢':brand==='Ruijie'?'🟤':'⚪'}</span>
        <b>${esc(brand)}</b>
      </span>
      <span class="ddc"><span class="tag tg">${total}</span> ▸</span>
    </div>
    <div class="ddsub" id="${subId}" style="display:none">
      ${Object.entries(types).sort((a,b)=>b[1].length-a[1].length).map(([model,devs])=>`
        <div class="dditem" style="font-size:11px" onclick="cm('mdd');filterInvByModel('${esc(model)}')">
          <span style="display:flex;align-items:center;gap:5px"><span class="tag tgr" style="font-size:10px">${esc(model)}</span></span>
          <span class="ddc">${devs.length} cihaz</span>
        </div>`).join('')}
    </div>`;
  });
  // Tag gruplaması
  let tagHtml='';
  Object.entries(d.by_tag).sort((a,b)=>b[1].length-a[1].length).slice(0,25).forEach(([tag,devs])=>{
    tagHtml+=`<div class="dditem" style="font-size:11px" onclick="cm('mdd');filterInvAndGo('${esc(tag)}')">
      <span class="tag tgr">${esc(tag)}</span><span class="ddc">${devs.length}</span>
    </div>`;
  });
  // Credential gruplaması
  let credHtml='';
  Object.entries(d.by_cred).sort((a,b)=>b[1].length-a[1].length).forEach(([cred,devs])=>{
    credHtml+=`<div class="dditem" style="font-size:11px" onclick="cm('mdd');filterInvAndGo('${esc(cred)}')">
      <span class="tag to">${esc(cred)}</span><span class="ddc">${devs.length} cihaz</span>
    </div>`;
  });
  body.innerHTML=`
    <div style="display:flex;gap:7px;margin-bottom:14px">
      <span class="tag tg">${d.total} toplam cihaz</span>
      <span class="tag tb">${Object.keys(d.by_brand).length} marka</span>
      <span class="tag tgr">${Object.keys(d.by_tag).length} tag</span>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px">
      <div>
        <div class="ss" style="font-size:12px;margin-top:0">🏭 Marka / Model</div>
        ${brandHtml}
      </div>
      <div>
        <div class="ss" style="font-size:12px;margin-top:0">🏷️ Tag Grupları</div>
        ${tagHtml}
      </div>
      <div>
        <div class="ss" style="font-size:12px;margin-top:0">🔑 Credential</div>
        ${credHtml}
      </div>
    </div>`;
}
function renderDDBackups(body,data){
  if(!data.length){body.innerHTML='<div class="empty"><div class="ei">💾</div><p>Backup yok</p></div>';return;}
  body.innerHTML=data.slice(0,15).map(day=>`
    <div style="margin-bottom:10px">
      <div style="font-size:10px;color:var(--text2);text-transform:uppercase;letter-spacing:1px;margin-bottom:4px;border-bottom:1px solid var(--border);padding-bottom:3px">📅 ${day.date} — ${day.count} dosya</div>
      ${day.files.slice(0,5).map(f=>`<div style="font-size:11px;padding:2px 4px;color:var(--text2)">${esc(f.name)} <span style="color:var(--text3)">${fmtSz(f.size)}</span></div>`).join('')}
      ${day.files.length>5?`<div style="font-size:10px;color:var(--text3);padding:2px 4px">+${day.files.length-5} daha…</div>`:''}
    </div>`).join('');
}
function toggleDD(id){const el=document.getElementById(id);el.style.display=el.style.display==='none'?'block':'none';}
function filterInvAndGo(q){
  // Clear all, set name filter, navigate
  _ifSelType.clear();_ifSelCred.clear();_ifSelTag.clear();
  const ni=document.getElementById('if-name'); if(ni) ni.value=q;
  const ii=document.getElementById('if-ip');   if(ii) ii.value='';
  gp('inventory');
}
function filterInvByModel(model){
  // Dashboard model satırına tıklanınca: model adına göre name filtresi uygula
  // Model bilgisi _iDModel haritasında tutulur (loadInventory sırasında doldurulur)
  _ifSelType.clear();_ifSelCred.clear();_ifSelTag.clear();_ifSelStatus.clear();
  const ni=document.getElementById('if-name'); if(ni) ni.value='';
  const ii=document.getElementById('if-ip');   if(ii) ii.value='';
  // Modele sahip cihazların IP'lerini _iDModel haritasından al
  _activeModelFilter = model;
  gp('inventory');
}

// ════════════════════════════════════════════════════
// VAULT
// ════════════════════════════════════════════════════
async function loadVault(){_vD=await api('GET','/api/vault/entries');renderVault();}
function renderVault(){
  const q=document.getElementById('vsrch').value.toLowerCase();
  const rows=Object.entries(_vD).filter(([s])=>s.toLowerCase().includes(q));
  const tb=document.getElementById('vtb');
  if(!rows.length){tb.innerHTML=`<tr><td colspan="3"><div class="empty"><div class="ei">🔐</div><p>Kayıt yok</p></div></td></tr>`;return;}
  tb.innerHTML=rows.map(([svc,f])=>`<tr>
    <td><b>${esc(svc)}</b></td>
    <td>${Object.entries(f).map(([k,v])=>`<span class="tag ${v.secret?'to':'tgr'}" style="margin:1px">${esc(k)}</span>`).join('')}</td>
    <td><div class="ab">
      <button class="btn btn-s btn-i btn-xs" onclick="viewVault('${esc(svc)}')" title="Görüntüle">👁</button>
      <button class="btn btn-s btn-i btn-xs" onclick="editVault('${esc(svc)}')" title="Düzenle">✏️</button>
      <button class="btn btn-d btn-i btn-xs" onclick="delVault('${esc(svc)}')" title="Sil">🗑</button>
    </div></td></tr>`).join('');
}
function openAddVault(){_mvFields={};document.getElementById('mv-svc').value='';document.getElementById('mv-orig').value='';document.getElementById('mv-t').textContent='Yeni Kayıt';renderMvF();om('mv');}
async function editVault(svc){
  const d=await api('GET',`/api/vault/entry/${enc(svc)}`);
  _mvFields={};for(const[k,v]of Object.entries(d))_mvFields[k]=v.value;
  document.getElementById('mv-svc').value=svc;document.getElementById('mv-orig').value=svc;
  document.getElementById('mv-t').textContent='Kaydı Düzenle';renderMvF();om('mv');
}
function renderMvF(){
  const el=document.getElementById('mv-fields');
  if(!Object.keys(_mvFields).length){el.innerHTML='<div style="color:var(--text3);font-size:11px;padding:5px 0 8px">Henüz alan yok.</div>';return;}
  el.innerHTML='<div class="fl">'+Object.entries(_mvFields).map(([k,v])=>{
    const sec=['password','token','secret','key','pass'].some(w=>k.toLowerCase().includes(w));
    return `<div class="fi"><span class="fn">${esc(k)}</span>
      <input class="fv" type="${sec?'password':'text'}" value="${esc(v)}" oninput="_mvFields['${esc(k)}']=this.value">
      <button class="btn btn-d btn-i btn-xs" onclick="delMvF('${esc(k)}')">✕</button></div>`;
  }).join('')+'</div>';
}
function addMvF(){const k=document.getElementById('mv-nk').value.trim(),v=document.getElementById('mv-nv').value;if(!k)return;_mvFields[k]=v;document.getElementById('mv-nk').value='';document.getElementById('mv-nv').value='';renderMvF();}
function delMvF(k){delete _mvFields[k];renderMvF();}
async function saveVault(){
  const svc=document.getElementById('mv-svc').value.trim(),orig=document.getElementById('mv-orig').value;
  if(!svc){toast('Servis adı boş','err');return;}
  if(!Object.keys(_mvFields).length){toast('En az bir alan gerekli','err');return;}
  try{
    if(orig&&orig!==svc){await api('DELETE',`/api/vault/entry/${enc(orig)}`);await api('POST','/api/vault/entry',{service:svc,fields:_mvFields});}
    else if(orig)await api('PUT',`/api/vault/entry/${enc(orig)}`,{fields:_mvFields});
    else await api('POST','/api/vault/entry',{service:svc,fields:_mvFields});
    toast('Kaydedildi','ok');cm('mv');loadVault();
  }catch(e){toast(e.message,'err');}
}
async function viewVault(svc){
  const d=await api('GET',`/api/vault/entry/${enc(svc)}`);
  document.getElementById('mvd-t').textContent=svc;
  document.getElementById('mvd-body').innerHTML='<div class="fl">'+Object.entries(d).map(([k,v])=>{
    const elId=`rv-${svc}-${k}`;const btnId=`rv-btn-${svc}-${k}`;
    if(v.secret){
      return `<div class="fi">
        <span class="fn">${esc(k)}</span>
        <span id="${elId}" style="letter-spacing:3px;color:var(--text3);flex:1" data-hidden="1" data-value="">•••••</span>
        <div style="display:flex;gap:4px;flex-shrink:0">
          <button class="btn btn-s btn-xs" id="${btnId}" onclick="revealF('${esc(svc)}','${esc(k)}')">👁 Göster</button>
          <button class="btn btn-b btn-xs" onclick="copyFieldVal('${esc(svc)}','${esc(k)}','${elId}')">📋</button>
        </div></div>`;
    }else{
      return `<div class="fi">
        <span class="fn">${esc(k)}</span>
        <span style="flex:1">${esc(v.value)}</span>
        <button class="btn btn-b btn-xs" onclick="navigator.clipboard.writeText(${JSON.stringify(v.value)}).then(()=>toast('Kopyalandı','ok'))">📋</button>
      </div>`;
    }
  }).join('')+'</div>';
  om('mvd');
}
async function revealF(s,f){
  const el=document.getElementById(`rv-${s}-${f}`);
  const btn=document.getElementById(`rv-btn-${s}-${f}`);
  if(el&&el.dataset.hidden==='0'){hideF(s,f);return;}
  const d=await api('GET',`/api/vault/reveal/${enc(s)}/${enc(f)}`);
  if(el){el.textContent=d.value;el.dataset.value=d.value;el.style.letterSpacing='normal';el.style.color='var(--text)';el.dataset.hidden='0';}
  if(btn){btn.textContent='🙈 Gizle';}
}
function hideF(s,f){
  const el=document.getElementById(`rv-${s}-${f}`);
  const btn=document.getElementById(`rv-btn-${s}-${f}`);
  if(el){el.textContent='•••••';el.style.letterSpacing='3px';el.style.color='var(--text3)';el.dataset.hidden='1';}
  if(btn){btn.textContent='👁 Göster';}
}
async function copyFieldVal(s,f,elId){
  let val='';
  const el=document.getElementById(elId);
  if(el&&el.dataset.value){val=el.dataset.value;}
  else{try{const d=await api('GET',`/api/vault/reveal/${enc(s)}/${enc(f)}`);val=d.value;}catch(e){toast('Kopyalanamadı','err');return;}}
  navigator.clipboard.writeText(val).then(()=>toast('Kopyalandı','ok')).catch(()=>toast('Kopyalanamadı','err'));
}
async function delVault(svc){if(!confirm(`"${svc}" silinecek. Emin misiniz?`))return;try{await api('DELETE',`/api/vault/entry/${enc(svc)}`);toast('Silindi','ok');loadVault();}catch(e){toast(e.message,'err');}}
// Pw Gen
function openPwGen(){om('mpw');genPw();}
async function genPw(){
  const d=await api('POST','/api/generate-password',{
    length:parseInt(document.getElementById('pg-len').value)||16,
    include_uppercase:document.getElementById('pg-u').checked,include_lowercase:document.getElementById('pg-l').checked,
    include_digits:document.getElementById('pg-d').checked,use_special_characters:document.getElementById('pg-s').checked,
    custom_special_characters:document.getElementById('pg-sc').value});
  document.getElementById('pw-val').textContent=d.password;
}
function cpPw(){navigator.clipboard.writeText(document.getElementById('pw-val').textContent).then(()=>toast('Kopyalandı','ok'));}

// ════════════════════════════════════════════════════
// INVENTORY
// ════════════════════════════════════════════════════
async function runStatusCheck(){
  const btn=document.getElementById('btn-status-check');
  if(btn){btn.disabled=true;btn.textContent='⏳ Kontrol ediliyor…';}

  // Aktif filtre varsa sadece görünen cihazları kontrol et
  const filteredRows = _invSortedRows(_invFilteredRows());
  const allRows      = _iD;
  const hasFilter    = filteredRows.length < allRows.length && filteredRows.length > 0;

  let body = {};
  if(hasFilter){
    body = {ips: filteredRows.map(d=>d.ip).filter(Boolean)};
    toast(`${filteredRows.length} cihaz için durum kontrolü başlatıldı`,'ok');
  } else {
    toast('Tüm cihazlar için durum kontrolü başlatıldı','ok');
  }

  try{
    const res = await api('POST','/api/device-status/run', body);
    toast(res.message,'ok');
    let tries=0;
    const poll=setInterval(async()=>{
      tries++;
      try{_iS=await api('GET','/api/device-status');renderInv();}catch(e){}
      if(tries>=60){clearInterval(poll);if(btn){btn.disabled=false;btn.textContent='🔄 Durum Kontrol';}}
    },5000);
  }catch(e){
    toast(e.message,'err');
    if(btn){btn.disabled=false;btn.textContent='🔄 Durum Kontrol';}
  }
}

async function runStatusCheckSingle(ip){
  try{
    toast(ip+' kontrol ediliyor…','ok');
    await api('POST','/api/device-status/run-single/'+encodeURIComponent(ip));
    let tries=0;
    const poll=setInterval(async()=>{
      tries++;
      try{
        _iS=await api('GET','/api/device-status');
        renderInv();
        const d=_iD[_curDevIdx];
        if(d && d.ip===ip){
          const _mst=_iS[ip]||{};
          const _mstClr=_mst.status==='green'?'#22c55e':_mst.status==='orange'?'#f97316':_mst.status==='red'?'#ef4444':'#6b7280';
          const _mstTxt=_mst.status==='green'?'Erişilebilir':_mst.status==='orange'?'Ping OK / Uzak bağlantı yok':_mst.status==='red'?'Erişilemiyor':'Henüz kontrol edilmedi';
          const _mstTime=_mst.checked_at?' ('+_mst.checked_at+')':'';
          const badge='<span style="display:inline-flex;align-items:center;gap:5px;padding:2px 8px;border-radius:20px;font-size:11px;background:'+_mstClr+'22;border:1px solid '+_mstClr+'55;color:'+_mstClr+'">'
            +'<span style="width:8px;height:8px;border-radius:50%;background:'+_mstClr+';box-shadow:0 0 5px '+_mstClr+'"></span>'
            +_mstTxt+_mstTime+'</span>';
          const el=document.getElementById('mid-cbadge');
          if(el) el.innerHTML=badge;
        }
      }catch(e){}
      if(tries>=5){
        clearInterval(poll);
        toast(ip+' durum güncellendi','ok');
      }
    },3000);
  }catch(e){ toast(e.message,'err'); }
}


// ════════════════════════════════════════════════════
// NETWORK MAP
// ════════════════════════════════════════════════════
let _nmLinks = [];

async function nmapBuild(){
  if(!confirm('Topoloji oluşturmak tüm cihazlara SSH bağlantısı gerektirebilir. Devam?')) return;
  const btn = document.getElementById('btn-nmap-build');
  const prg = document.getElementById('nmap-progress');
  const bar = document.getElementById('nmap-pbar');
  const msg = document.getElementById('nmap-prog-msg');
  const st  = document.getElementById('nmap-status');
  btn.disabled=true; prg.style.display=''; st.textContent='Çalışıyor…';
  document.getElementById('btn-nmap-export-csv').style.display='none';
  document.getElementById('btn-nmap-export-xml').style.display='none';

  try {
    const res = await api('POST','/api/netmap/build');
    const jid = res.job_id;
    // Poll
    const poll = setInterval(async()=>{
      try {
        const s = await api('GET','/api/netmap/status');
        bar.style.width = (s.progress||0)+'%';
        msg.textContent = s.message||'';
        if(s.status==='done'){
          clearInterval(poll);
          btn.disabled=false;
          st.textContent=s.message;
          await nmapLoad();
          document.getElementById('btn-nmap-export-csv').style.display='';
          document.getElementById('btn-nmap-export-xml').style.display='';
          setTimeout(()=>{ prg.style.display='none'; },2000);
        } else if(s.status==='error'){
          clearInterval(poll);
          btn.disabled=false;
          st.textContent='Hata: '+s.message;
          prg.style.display='none';
        }
      } catch(e){ clearInterval(poll); btn.disabled=false; }
    },1500);
  } catch(e){
    btn.disabled=false; st.textContent='Hata: '+e.message; prg.style.display='none';
  }
}

async function nmapLoad(){
  try {
    _nmLinks = await api('GET','/api/netmap/links');
    nmapRender();
  } catch(e){ _nmLinks=[]; }
}

function _nmapFilteredRows(){
  const q = (document.getElementById('nmap-filter')||{value:''}).value.toLowerCase().trim();
  if(!q) return _nmLinks;
  return _nmLinks.filter(l=>
    (l.local_device||'').toLowerCase().includes(q)||
    (l.remote_device||'').toLowerCase().includes(q)||
    (l.local_port||'').toLowerCase().includes(q)||
    (l.remote_port||'').toLowerCase().includes(q)||
    (l.local_po||'').toLowerCase().includes(q)||
    (l.remote_po||'').toLowerCase().includes(q)||
    (l.active_vlans||[]).some(v=>String(v).includes(q))||
    (l.local_vlans||[]).some(v=>String(v).includes(q))
  );
}

function _fmtVlans(vlans){
  if(!vlans||!vlans.length) return '<span style="color:var(--text3)">—</span>';
  if(vlans.length<=6) return vlans.join(', ');
  return `${vlans.slice(0,5).join(', ')} <span title="${vlans.join(',')}" style="cursor:help;color:var(--accent2)">+${vlans.length-5}</span>`;
}

function nmapRender(){
  const rows = _nmapFilteredRows();
  const tb   = document.getElementById('nmap-tbody');
  document.getElementById('nmap-count').textContent =
    `${rows.length} / ${_nmLinks.length} bağlantı`;
  if(!rows.length){
    tb.innerHTML='<tr><td colspan="12"><div class="empty"><div class="ei">🗺️</div>'
      +'<p>Bağlantı yok — önce topoloji oluşturun</p></div></td></tr>';
    return;
  }
  tb.innerHTML = rows.map(l=>{
    const hasErr = l.ssh_error ? `title="${esc(l.ssh_error)}" style="cursor:help"` : '';
    const errBadge = l.ssh_error
      ? `<span ${hasErr} style="color:#f97316;font-size:10px">⚠ SSH</span>` : '';
    const vlanMatch = (l.local_vlans&&l.local_vlans.length&&l.remote_vlans&&l.remote_vlans.length)
      ? (l.active_vlans&&l.active_vlans.length
          ? '<span style="color:#22c55e">✓</span>'
          : '<span style="color:#ef4444" title="VLAN uyuşmazlığı">✗</span>')
      : '';
    return `<tr>
      <td><b style="color:var(--accent)">${esc(l.local_device)}</b></td>
      <td><code style="font-size:11px">${esc(l.local_port)}</code></td>
      <td><b style="color:var(--accent2)">${esc(l.remote_device)}</b></td>
      <td><code style="font-size:11px">${esc(l.remote_port)}</code></td>
      <td>${l.local_po?`<span class="tag tb">${esc(l.local_po)}</span>`:''}</td>
      <td style="font-size:10px;max-width:150px">${esc((l.local_po_members||[]).join(', '))||'—'}</td>
      <td style="font-size:11px">${_fmtVlans(l.local_vlans)}</td>
      <td>${l.remote_po?`<span class="tag tg">${esc(l.remote_po)}</span>`:''}</td>
      <td style="font-size:11px">${_fmtVlans(l.remote_vlans)}</td>
      <td style="font-size:11px"><b>${_fmtVlans(l.active_vlans)}</b> ${vlanMatch}</td>
      <td><span class="tag tgr" style="font-size:10px">${esc(l.protocol||'?')}</span></td>
      <td>${errBadge||'<span style="color:#22c55e;font-size:11px">✓</span>'}</td>
    </tr>`;
  }).join('');
}

function nmapExportCsv(){
  const rows = _nmapFilteredRows();
  const hdr = ['Lokal Cihaz','Lokal Port','Uzak Cihaz','Uzak Port',
                'Lokal PO','Lokal PO Üyeler','Lokal VLAN',
                'Uzak PO','Uzak VLAN','Aktif VLAN','Protokol','SSH Hata'];
  const csv = [hdr, ...rows.map(l=>[
    l.local_device, l.local_port, l.remote_device, l.remote_port,
    l.local_po||'', (l.local_po_members||[]).join(';'),
    (l.local_vlans||[]).join(';'),
    l.remote_po||'', (l.remote_vlans||[]).join(';'),
    (l.active_vlans||[]).join(';'),
    l.protocol||'', l.ssh_error||''
  ])].map(r=>r.map(c=>'"'+(String(c).replace(/"/g,'""'))+'"').join(',')).join('\n');
  const a=document.createElement('a');
  a.href='data:text/csv;charset=utf-8,\uFEFF'+encodeURIComponent(csv);
  a.download='network_map.csv'; a.click();
}

async function nmapExportDrawio(){
  try {
    const resp = await fetch('/api/netmap/drawio');
    if(!resp.ok){const e=await resp.json();toast(e.error,'err');return;}
    const blob = await resp.blob();
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href=url; a.download='network_map.drawio'; a.click();
    URL.revokeObjectURL(url);
  } catch(e){ toast(e.message,'err'); }
}

async function loadInventory(){
  _iD=await api('GET','/api/inventory');
  try{_iS=await api('GET','/api/device-status');}catch(e){_iS={};}
  // device_details'dan model haritası oluştur
  try{
    const dd=await api('GET','/api/device-details');
    _iDModel={};
    Object.entries(dd).forEach(([ip,d])=>{ if(d.model) _iDModel[ip]=d.model; });
  }catch(e){ _iDModel={}; }
  renderInv();
}
// ════════════════════════════════════════════════════
// CSV EXPORT
// ════════════════════════════════════════════════════
function toggleCsvMenu(){
  const m=document.getElementById('csv-menu');
  if(!m) return;
  const show = m.style.display==='none';
  m.style.display = show ? 'block' : 'none';
  if(show){
    // Populate tag list
    const tags=[...new Set(_iD.flatMap(d=>d.tags||[]))].sort();
    const el=document.getElementById('csv-tag-items');
    if(el){
      if(tags.length){
        el.innerHTML='<div style="padding:4px 12px;font-size:10px;color:var(--text3);text-transform:uppercase;letter-spacing:.8px;border-top:1px solid var(--border);margin-top:4px">Tag\'a göre</div>'
          + tags.map(t=>`<div class="udrop-item" onclick="exportCsv('tag','${esc(t)}')">${esc(t)}</div>`).join('');
      }else{
        el.innerHTML='';
      }
    }
    // Close on outside click
    setTimeout(()=>document.addEventListener('click', function h(e){
      if(!document.getElementById('csv-menu')?.contains(e.target)){
        document.getElementById('csv-menu').style.display='none';
        document.removeEventListener('click',h);
      }
    }), 10);
  }
}

function _devCollector(ip){
  // Try to get collector data from _devDetails cache
  return window._devDetails?.[ip] || null;
}

async function exportCsv(mode, tag){
  document.getElementById('csv-menu').style.display='none';

  // Decide which devices to export
  let devices = [];
  if(mode==='all'){
    devices = _iD.map((d,i)=>({...d, _idx:i}));
  } else if(mode==='filtered'){
    devices = _invFilteredRows();
  } else if(mode==='tag'){
    devices = _iD.map((d,i)=>({...d,_idx:i})).filter(d=>(d.tags||[]).includes(tag));
  }

  if(!devices.length){ toast('Dışa aktarılacak cihaz yok','err'); return; }
  toast(`${devices.length} cihaz CSV hazırlanıyor…`,'ok');

  // Fetch collector details for all devices in parallel (from API)
  const details = {};
  await Promise.all(devices.map(async d=>{
    try{
      const r = await api('GET',`/api/device/${d._idx}/detail`);
      if(r.collector) details[d.ip] = r.collector;
    }catch(_){}
  }));

  // Build CSV
  const cols = [
    {h:'Name',         f:d=>d.name||''},
    {h:'IP',           f:d=>d.ip||''},
    {h:'Device Type',  f:d=>d.device_type||''},
    {h:'Credential',   f:d=>d.credential_id||''},
    {h:'Tags',         f:d=>(d.tags||[]).join('; ')},
    {h:'Notes',        f:d=>d.notes||''},
    {h:'Additional IPs',f:d=>{
      const a=d.additional_ips;
      if(!a) return '';
      return Array.isArray(a)?a.join('; '):String(a);
    }},
    // Collector fields
    {h:'Hostname',     f:d=>details[d.ip]?.hostname||''},
    {h:'Brand',        f:d=>{
      if(details[d.ip]?.brand) return details[d.ip].brand;
      const dt=(d.device_type||'').toLowerCase();
      if(dt.includes('forti'))   return 'Fortinet';
      if(dt.includes('cisco'))   return 'Cisco';
      if(dt.includes('huawei'))  return 'Huawei';
      if(dt.includes('h3c')||dt.includes('comware')) return 'H3C';
      if(dt.includes('extreme')) return 'Extreme Networks';
      if(dt.includes('ruijie')||dt.includes('rgos')) return 'Ruijie';
      if(dt.includes('f5')||dt.includes('bigip'))    return 'F5';
      if(dt.includes('dell'))    return 'Dell';
      if(dt.includes('hp'))      return 'HP';
      return '';
    }},
    {h:'Model',        f:d=>details[d.ip]?.model||''},
    {h:'Serial No',    f:d=>details[d.ip]?.serial_no||''},
    {h:'Software Ver', f:d=>details[d.ip]?.software_version||''},
    {h:'Uptime',       f:d=>details[d.ip]?.uptime||''},
    {h:'HA Mode',      f:d=>details[d.ip]?.ha_mode||''},
    {h:'HA Role',      f:d=>details[d.ip]?.ha_role||''},
    {h:'HA Serial',    f:d=>details[d.ip]?.ha_serial||''},
    {h:'Last Collected',f:d=>details[d.ip]?.last_collected||details[d.ip]?.collected_at||''},
  ];

  function csvCell(v){
    const s = String(v??'').replace(/"/g,'""');
    return /[",\n\r]/.test(s) ? `"${s}"` : s;
  }

  const header = cols.map(c=>csvCell(c.h)).join(',');
  const rows   = devices.map(d=>cols.map(c=>csvCell(c.f(d))).join(','));
  const csv    = [header,...rows].join('\r\n');

  const ts  = new Date().toISOString().slice(0,19).replace(/[:T]/g,'-');
  const fname = mode==='tag' ? `inventory_${tag}_${ts}.csv`
              : mode==='filtered' ? `inventory_filtered_${ts}.csv`
              : `inventory_all_${ts}.csv`;

  const blob = new Blob(['\uFEFF'+csv], {type:'text/csv;charset=utf-8'});
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href=url; a.download=fname;
  document.body.appendChild(a); a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  toast(`${fname} indirildi`,'ok');
}

// ════════════════════════════════════════════════════
// INVENTORY MULTI-COLUMN FILTER
// ════════════════════════════════════════════════════
let _ifSelType = new Set();  // selected device_types
let _ifSelCred = new Set();  // selected credential_ids
let _ifSelTag  = new Set();  // selected tags (AND logic within tags)
let _ifDropOpen = null;      // currently open dropdown key

let _ifSelStatus = new Set();
let _activeModelFilter = '';   // dashboard model tıklaması filtresi
let _iDModel = {};              // ip → model haritası (device_details'dan doldurulur)

function toggleStatusDrop(){
  const d=document.getElementById('if-status-drop');
  d.style.display=d.style.display==='none'?'':'none';
}
function onStatusFilter(){
  _ifSelStatus.clear();
  document.querySelectorAll('#if-status-drop input:checked').forEach(cb=>_ifSelStatus.add(cb.value));
  const lbl = _ifSelStatus.size ? `🔵 Durum (${_ifSelStatus.size})` : '🔵 Durum…';
  document.getElementById('if-status-label').textContent=lbl;
  _updateInvFilterLabels();
  renderInv();
}
// Close status drop on outside click
document.addEventListener('click',(e)=>{
  if(!e.target.closest('#if-status-btn')&&!e.target.closest('#if-status-drop')){
    const d=document.getElementById('if-status-drop');
    if(d) d.style.display='none';
  }
});

function _invFilteredRows(){
  const fName = (document.getElementById('if-name')?.value||'').toLowerCase().trim();
  const fIp   = (document.getElementById('if-ip')?.value||'').toLowerCase().trim();
  return _iD.map((d,i)=>({...d,_idx:i})).filter(d=>{
    if(fName && !(d.name||'').toLowerCase().includes(fName)) return false;
    if(fIp   && !(d.ip||'').toLowerCase().includes(fIp))   return false;
    if(_ifSelType.size && !_ifSelType.has(d.device_type||'')) return false;
    if(_ifSelCred.size && !_ifSelCred.has(d.credential_id||'')) return false;
    if(_ifSelTag.size){
      const dtags = new Set(d.tags||[]);
      for(const t of _ifSelTag){ if(!dtags.has(t)) return false; }
    }
    if(_ifSelStatus.size){
      const st=(_iS[d.ip]||{}).status||'unknown';
      if(!_ifSelStatus.has(st)) return false;
    }
    if(_activeModelFilter){
      const mdl=(_iDModel[d.ip]||d.model||d.device_type||'').toLowerCase();
      if(!mdl.includes(_activeModelFilter.toLowerCase())) return false;
    }
    return true;
  });
}

function _invAllValues(field){
  if(field==='type') return [...new Set(_iD.map(d=>d.device_type||''))].sort();
  if(field==='cred') return [...new Set(_iD.map(d=>d.credential_id||''))].sort();
  if(field==='tag')  return [...new Set(_iD.flatMap(d=>d.tags||[]))].sort();
  return [];
}

function openInvDropdown(field){
  // Toggle
  if(_ifDropOpen===field){
    closeInvDropdown(); return;
  }
  closeInvDropdown();
  _ifDropOpen = field;
  const drop = document.getElementById(`if-${field}-drop`);
  if(!drop) return;

  const selSet = field==='type'?_ifSelType : field==='cred'?_ifSelCred : _ifSelTag;
  const vals   = _invAllValues(field);

  // Build dropdown content
  let html = `<input class="inv-drop-srch" placeholder="Ara…" oninput="filterInvDropItems(this,'${field}')" onclick="event.stopPropagation()">`;
  if(selSet.size){
    html += `<div class="inv-drop-item" style="color:var(--danger);font-size:11px" onclick="clearInvField('${field}')">✕ Seçimi temizle</div>`;
  }
  html += vals.map(v=>{
    const sel = selSet.has(v);
    return `<div class="inv-drop-item${sel?' sel':''}" data-val="${esc(v)}" onclick="toggleInvFilter('${field}','${esc(v)}')">
      <span class="ck">${sel?'✓':''}</span>
      <span>${v||'<em style="color:var(--text3)">boş</em>'}</span>
    </div>`;
  }).join('');
  drop.innerHTML = html;
  drop.style.display = 'block';

  // Close on outside click
  setTimeout(()=>document.addEventListener('click',_invOutsideClick,true),10);
}

function filterInvDropItems(input, field){
  const q = input.value.toLowerCase();
  input.parentElement.querySelectorAll('.inv-drop-item[data-val]').forEach(el=>{
    el.style.display = el.dataset.val.toLowerCase().includes(q)?'':'none';
  });
}

function _invOutsideClick(e){
  const openDrop = document.getElementById(`if-${_ifDropOpen}-drop`);
  const openBtn  = document.getElementById(`if-${_ifDropOpen}-btn`);
  if(openDrop && !openDrop.contains(e.target) && !openBtn?.contains(e.target)){
    closeInvDropdown();
  }
}

function closeInvDropdown(){
  if(_ifDropOpen){
    document.getElementById(`if-${_ifDropOpen}-drop`).style.display='none';
    document.removeEventListener('click',_invOutsideClick,true);
    _ifDropOpen = null;
  }
}

function toggleInvFilter(field, val){
  const selSet = field==='type'?_ifSelType : field==='cred'?_ifSelCred : _ifSelTag;
  if(selSet.has(val)) selSet.delete(val); else selSet.add(val);
  // Update checkbox in open dropdown without closing
  const drop = document.getElementById(`if-${field}-drop`);
  drop?.querySelectorAll(`.inv-drop-item[data-val]`).forEach(el=>{
    const sel = selSet.has(el.dataset.val);
    el.classList.toggle('sel', sel);
    el.querySelector('.ck').textContent = sel?'✓':'';
  });
  // Refresh clear button at top of dropdown
  const clearEl = drop?.querySelector('.inv-drop-item[style*="danger"]');
  if(clearEl) clearEl.style.display = selSet.size?'':'none';
  _updateInvFilterLabels();
  renderInv();
}

function clearInvField(field){
  if(field==='type') _ifSelType.clear();
  else if(field==='cred') _ifSelCred.clear();
  else _ifSelTag.clear();
  openInvDropdown(field);  // re-render dropdown
  _updateInvFilterLabels();
  renderInv();
}

function _updateInvFilterLabels(){
  const defs = {type:'📦 Type…', cred:'🔑 Credential…', tag:'🏷️ Tag…'};
  const sets  = {type:_ifSelType, cred:_ifSelCred, tag:_ifSelTag};
  for(const [f,s] of Object.entries(sets)){
    const lbl = document.getElementById(`if-${f}-label`);
    const btn = document.getElementById(`if-${f}-btn`);
    if(!lbl) continue;
    if(s.size===0){
      lbl.textContent = defs[f];
      btn?.style.removeProperty('border-color');
    } else {
      const preview = [...s].slice(0,2).join(', ') + (s.size>2?` +${s.size-2}`:'');
      lbl.textContent = preview;
      if(btn) btn.style.borderColor = 'var(--accent)';
    }
  }
  const hasAny = _ifSelType.size||_ifSelCred.size||_ifSelTag.size||_ifSelStatus.size||_activeModelFilter||
    (document.getElementById('if-name')?.value||'')||
    (document.getElementById('if-ip')?.value||'');
  const stBtn=document.getElementById('if-status-btn');
  if(stBtn) stBtn.style.borderColor=_ifSelStatus.size?'var(--accent)':'';
  // Model filtresi aktifse filtre çubuğunda göster
  let mfEl=document.getElementById('if-model-badge');
  if(_activeModelFilter){
    if(!mfEl){
      mfEl=document.createElement('span');
      mfEl.id='if-model-badge';
      mfEl.style.cssText='padding:4px 8px;background:var(--accent);color:#fff;border-radius:var(--r);font-size:11px;cursor:pointer';
      mfEl.title='Model filtresini temizle';
      mfEl.onclick=function(){_activeModelFilter='';_updateInvFilterLabels();renderInv();};
      const bar=document.getElementById('inv-filter-bar');
      if(bar) bar.insertBefore(mfEl, bar.firstChild);
    }
    mfEl.textContent='📦 '+_activeModelFilter+' ✕';
  } else if(mfEl){ mfEl.remove(); }
  const cb = document.getElementById('if-clear-btn');
  if(cb) cb.style.display = hasAny?'':'none';
}

function clearInvFilters(){
  _ifSelType.clear(); _ifSelCred.clear(); _ifSelTag.clear(); _ifSelStatus.clear();
  document.getElementById('if-name').value='';
  document.getElementById('if-ip').value='';
  document.getElementById('if-status-label').textContent='🔵 Durum…';
  document.querySelectorAll('#if-status-drop input').forEach(cb=>cb.checked=false);
  _activeModelFilter='';
  _updateInvFilterLabels();
  renderInv();
}

// ── Inventory Sort ─────────────────────────────────────
let _invSort = {field:'name', dir:1}; // dir: 1=asc, -1=desc

function sortInv(field){
  if(_invSort.field===field){
    _invSort.dir *= -1;
  } else {
    _invSort.field=field;
    _invSort.dir=1;
  }
  // Update indicators
  ['status','name','ip','device_type','credential_id'].forEach(f=>{
    const el=document.getElementById('srt-'+f);
    if(!el) return;
    if(f===_invSort.field) el.textContent=_invSort.dir===1?'▲':'▼';
    else el.textContent='';
  });
  renderInv();
}

function _invSortedRows(rows){
  const {field, dir} = _invSort;
  return [...rows].sort((a,b)=>{
    let av, bv;
    if(field==='status'){
      const order={green:0,orange:1,red:2,unknown:3};
      av = order[(_iS[a.ip]||{}).status||'unknown']??3;
      bv = order[(_iS[b.ip]||{}).status||'unknown']??3;
    } else if(field==='ip'){
      // Numeric IP sort
      const toNum=ip=>(ip||'').split('.').reduce((acc,o)=>acc*256+parseInt(o||0),0);
      av=toNum(a.ip); bv=toNum(b.ip);
    } else {
      av=(a[field]||'').toLowerCase();
      bv=(b[field]||'').toLowerCase();
    }
    if(av<bv) return -1*dir;
    if(av>bv) return  1*dir;
    return 0;
  });
}

function renderInv(){
  _updateInvFilterLabels();
  const rows = _invSortedRows(_invFilteredRows());
  const tb = document.getElementById('itb');
  if(!rows.length){
    tb.innerHTML=`<tr><td colspan="7"><div class="empty"><div class="ei">🖧</div><p>Cihaz bulunamadı</p></div></td></tr>`;
    document.getElementById('if-count').textContent='';
    return;
  }
  const total = _iD.length;
  document.getElementById('if-count').textContent = rows.length < total ? `${rows.length} / ${total} cihaz` : `${total} cihaz`;
  tb.innerHTML=rows.map(d=>{
    const idx=d._idx;
    const dt=d.device_type||'';
    const tc=dt.includes('cisco')?'tb':dt.includes('huawei')?'tg':dt.includes('forti')?'to':dt.includes('bigip')||dt.includes('f5')||dt.includes('velos')?'tr':'tgr';
    const tags=(d.tags||[]).slice(0,4).map(t=>{
      const active=_ifSelTag.has(t);
      return `<span class="tag tgr" style="margin:1px;cursor:pointer;${active?'outline:1px solid var(--accent)':''}" onclick="event.stopPropagation();toggleInvFilter('tag','${esc(t)}')">${esc(t)}</span>`;
    }).join('')+(d.tags?.length>4?` <span class="tag tgr">+${d.tags.length-4}</span>`:'');
    const admB=_role==='admin'?`<button class="btn btn-s btn-i btn-xs" onclick="event.stopPropagation();openAddInv(${idx})">✏️</button><button class="btn btn-d btn-i btn-xs" onclick="event.stopPropagation();delInv(${idx})">🗑</button>`:'';
    const _st=_iS[d.ip]||{};
    const _stColor=_st.status==='green'?'#22c55e':_st.status==='orange'?'#f97316':_st.status==='red'?'#ef4444':'#6b7280';
    const _stLabel=_st.status==='green'?'Erişilebilir':_st.status==='orange'?'Ping OK / Uzak bağlantı yok':_st.status==='red'?'Erişilemiyor':'Kontrol edilmedi';
    const _stSub=_st.checked_at?`<br><span style="font-size:9px;color:var(--text3)">${_st.checked_at.slice(5,16)}</span>`:'<br><span style="font-size:9px;color:var(--text3)">—</span>';
    const _macTip = d.mac_address ? ` title="MAC: ${esc(d.mac_address)}${d.serial_no ? ' | SN: '+esc(d.serial_no) : ''}"` : '';
    return `<tr style="cursor:pointer" onclick="viewInv(${idx})">
      <td style="text-align:center">
        <span title="${_stLabel}" style="display:inline-block;width:14px;height:14px;border-radius:50%;background:${_stColor};box-shadow:0 0 6px ${_stColor}88">
        </span>${_stSub}
      </td>
      <td${_macTip}><b style="color:var(--accent)">${esc(d.name)}</b>${d.serial_no||d.mac_address?`<br><span style="font-size:9px;color:var(--text3);font-family:monospace">${d.serial_no?'SN:'+esc(d.serial_no):'MAC:'+esc(d.mac_address)}</span>`:''}</td>
      <td><code style="color:var(--accent2)">${esc(d.ip)}</code></td>
      <td><span class="tag ${tc}" style="cursor:pointer" onclick="event.stopPropagation();toggleInvFilter('type','${esc(dt)}')">${esc(dt)}</span></td>
      <td><span class="tag tgr" style="cursor:pointer" onclick="event.stopPropagation();toggleInvFilter('cred','${esc(d.credential_id||'')}')">${esc(d.credential_id||'—')}</span></td>
      <td>${tags}</td>
      <td class="adm"><div class="ab">
        <button class="btn btn-s btn-i btn-xs" onclick="event.stopPropagation();viewInv(${idx})">👁</button>${admB}
      </div></td></tr>`;
  }).join('');
  document.querySelectorAll('.adm').forEach(el=>el.style.display=_role==='admin'?'':'none');
}
// Inventory CRUD
function openAddInv(idx){
  document.getElementById('mi-idx').value=idx;
  document.getElementById('mi-t').textContent=idx===-1?'Cihaz Ekle':'Cihaz Düzenle';
  if(idx===-1){['mi-name','mi-ip','mi-port','mi-cred','mi-mac','mi-serial','mi-tags'].forEach(id=>document.getElementById(id).value='');document.getElementById('mi-type').value='cisco_ios';}
  else{const d=_iD[idx];document.getElementById('mi-name').value=d.name||'';document.getElementById('mi-ip').value=d.ip||'';document.getElementById('mi-port').value=d.port||'';document.getElementById('mi-type').value=d.device_type||'cisco_ios';document.getElementById('mi-cred').value=d.credential_id||'';document.getElementById('mi-mac').value=d.mac_address||'';document.getElementById('mi-serial').value=d.serial_no||'';document.getElementById('mi-tags').value=(d.tags||[]).join(', ');}
  om('mi');
}
async function saveInv(){
  const idx=parseInt(document.getElementById('mi-idx').value),name=document.getElementById('mi-name').value.trim(),ip=document.getElementById('mi-ip').value.trim();
  if(!name||!ip){toast('Ad ve IP gerekli','err');return;}
  const port=document.getElementById('mi-port').value;
  const _mac=document.getElementById('mi-mac').value.trim();
  const _sn=document.getElementById('mi-serial').value.trim();
  const obj={name,ip,device_type:document.getElementById('mi-type').value,credential_id:document.getElementById('mi-cred').value.trim(),tags:document.getElementById('mi-tags').value.split(',').map(t=>t.trim()).filter(Boolean)};
  if(_mac)obj.mac_address=_mac;
  if(_sn)obj.serial_no=_sn;
  if(port)obj.port=parseInt(port);
  try{if(idx===-1)await api('POST','/api/inventory',obj);else await api('PUT',`/api/inventory/${idx}`,obj);toast('Kaydedildi','ok');cm('mi');loadInventory();}
  catch(e){toast(e.message,'err');}
}
async function delInv(idx){if(!confirm(`"${_iD[idx].name}" silinecek?`))return;try{await api('DELETE',`/api/inventory/${idx}`);toast('Silindi','ok');loadInventory();}catch(e){toast(e.message,'err');}}

// ════════════════════════════════════════════════════
// DEVICE DETAIL MODAL
// ════════════════════════════════════════════════════
async function viewInv(idx){
  // Önceki SSH bağlantısını kapat
  if(_sshSid){ sshDisconnect(); }
  _sshClosed=false; _sshLogName=null;
  _curDevIdx=idx;_devBkFiles=[];
  const d=_iD[idx];
  document.getElementById('mid-name').textContent=d.name;
  document.getElementById('mid-ip').textContent=d.ip;
  // MAC / Serial rozeti
  const _macBadge = d.mac_address
    ? `<span style="font-family:monospace;font-size:11px;color:var(--text3);margin-right:8px" title="MAC Adresi">🔌 ${esc(d.mac_address)}</span>` : '';
  const _snBadge = d.serial_no
    ? `<span style="font-family:monospace;font-size:11px;color:var(--text3)" title="Serial No">🏷 ${esc(d.serial_no)}</span>` : '';
  const _macSnEl = document.getElementById('mid-mac-sn');
  if(_macSnEl) _macSnEl.innerHTML = _macBadge + _snBadge;
  // Durum rozeti
  const _mst=_iS[d.ip]||{};
  const _mstClr=_mst.status==='green'?'#22c55e':_mst.status==='orange'?'#f97316':_mst.status==='red'?'#ef4444':'#6b7280';
  const _mstTxt=_mst.status==='green'?'Erişilebilir':_mst.status==='orange'?'Ping OK / Uzak bağlantı yok':_mst.status==='red'?'Erişilemiyor':'Henüz kontrol edilmedi';
  const _mstTime=_mst.checked_at?` (${_mst.checked_at})`:''; 
  const _mstBadge=`<span style="display:inline-flex;align-items:center;gap:5px;padding:2px 8px;border-radius:20px;font-size:11px;background:${_mstClr}22;border:1px solid ${_mstClr}55;color:${_mstClr}">`+
    `<span style="width:8px;height:8px;border-radius:50%;background:${_mstClr};box-shadow:0 0 5px ${_mstClr}"></span>`+
    `${_mstTxt}${_mstTime}</span>`;
  document.getElementById('mid-cbadge').innerHTML=_mstBadge;
  document.getElementById('mid-hmm').innerHTML='';
  document.getElementById('mid-cbadge').innerHTML='';
  document.getElementById('nb-cnt').innerHTML='';
  document.getElementById('bk-cnt').innerHTML='';
  document.getElementById('mid-col-btn').disabled=false;
  document.getElementById('mid-nb-btn').disabled=false;
  const eb=document.getElementById('mid-edit-btn');if(eb)eb.onclick=()=>{cm('mid');openAddInv(idx);};
  // SSH UI sıfırla
  const connBtn=document.getElementById('ssh-conn-btn');
  const discBtn=document.getElementById('ssh-disc-btn');
  const logBtn=document.getElementById('ssh-log-dl-btn');
  if(connBtn){connBtn.disabled=false;}
  if(discBtn){discBtn.style.display='none';}
  if(logBtn){logBtn.style.display='none';}
  sshSetStatus('Bağlı değil');
  sshClear();
  swDTab('info');
  renderDTabInfo(d,idx);
  om('mid');
  // async load
  try{
    const r=await api('GET',`/api/device/${idx}/detail`);
    _devBkFiles=r.backups||[];
    renderDTabHw(r.collector,d);
    renderDTabNb(r.collector);
    renderDTabBk(r.backups,d);
    // badge counts
    const bCnt=r.backups?.length||0,nbCnt=r.collector?.neighbors?.length||0;
    if(bCnt)document.getElementById('bk-cnt').innerHTML=`<span class="tag tb" style="padding:1px 5px;font-size:10px">${bCnt}</span>`;
    if(nbCnt)document.getElementById('nb-cnt').innerHTML=`<span class="tag tg" style="padding:1px 5px;font-size:10px">${nbCnt}</span>`;
    // hostname mismatch check
    const hn=r.collector?.hostname;
    if(hn&&hn.toLowerCase()!==d.name.toLowerCase()){
      document.getElementById('mid-hmm').innerHTML=`<div class="hmm-banner">⚠️ Kayıtlı ad: <b>${esc(d.name)}</b> &nbsp;|&nbsp; Gerçek hostname: <b>${esc(hn)}</b></div>`;
    }
  }catch(e){
    renderDTabHw(null,d);renderDTabNb(null);renderDTabBk([],d);
  }
}

function swDTab(name){
  document.querySelectorAll('.dtab').forEach(b=>b.classList.toggle('act',b.dataset.dt===name));
  ['info','hw','nb','bk','ssh'].forEach(t=>{
    const el=document.getElementById('dtab-'+t);
    if(el) el.style.display=t===name?'block':'none';
  });
  if(name==='ssh') onSshTabOpen();
}

function renderDTabInfo(d,idx){
  const ips=(d.additional_ips||[]);
  const extraHtml=ips.length?`<div class="icard"><div class="il">Ek IP'ler</div><div class="iv bl">${ips.join('<br>')}</div></div>`:'';
  const tags=(d.tags||[]).map(t=>`<span class="tag tgr" style="margin:2px">${esc(t)}</span>`).join('');
  document.getElementById('dtab-info').innerHTML=`
    <div class="inv-grid">
      <div class="icard"><div class="il">Cihaz Adı</div><div class="iv ac">${esc(d.name)}</div></div>
      <div class="icard"><div class="il">IP Adresi</div><div class="iv bl">${esc(d.ip)}</div></div>
      <div class="icard"><div class="il">Cihaz Tipi</div><div class="iv">${esc(d.device_type||'—')}</div></div>
      <div class="icard"><div class="il">Port</div><div class="iv">${d.port||'varsayılan'}</div></div>
      <div class="icard"><div class="il">Credential ID</div><div class="iv or">${esc(d.credential_id||'—')}</div></div>
      ${extraHtml}
    </div>
    <div><div style="font-size:10px;color:var(--text3);text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">Tags</div>
    ${tags||'<span style="color:var(--text3)">—</span>'}</div>
    <div style="margin-top:14px">
      <div style="font-size:10px;color:var(--text3);text-transform:uppercase;letter-spacing:1px;margin-bottom:6px;display:flex;align-items:center;justify-content:space-between">
        Not
        <button class="btn btn-s btn-xs" onclick="toggleNoteEdit(${idx})">✏️ Düzenle</button>
      </div>
      <div id="note-view-${idx}" style="color:var(--text2);font-size:12px;min-height:28px;white-space:pre-wrap">${esc(d.notes||'—')}</div>
      <div id="note-edit-${idx}" style="display:none">
        <textarea id="note-ta-${idx}" style="width:100%;background:var(--bg3);border:1px solid var(--border);border-radius:var(--r);color:var(--text);font-family:inherit;font-size:12px;padding:8px 10px;outline:none;resize:vertical;min-height:60px" onkeydown="if(event.ctrlKey&&event.key==='Enter')saveNote(${idx})">${esc(d.notes||'')}</textarea>
        <div style="display:flex;gap:6px;margin-top:6px">
          <button class="btn btn-p btn-xs" onclick="saveNote(${idx})">💾 Kaydet</button>
          <button class="btn btn-s btn-xs" onclick="toggleNoteEdit(${idx},true)">İptal</button>
        </div>
      </div>
    </div>`;
}

function renderDTabHw(col,d){
  const el=document.getElementById('dtab-hw');
  if(!col){
    el.innerHTML=`<div class="empty"><div class="ei">📦</div><p>Envanter verisi yok.</p><p style="margin-top:6px;font-size:11px">⚡ "Envanter Al" ile anlık toplayabilirsiniz.</p></div>`;
    return;
  }
  // Timestamp
  let html=col.collected_at?`<div style="color:var(--text3);font-size:10px;margin-bottom:12px">Son güncelleme: ${esc(col.source_file||'')}</div>`:'';
  // Main fields
  const mainFields=[
    {l:'Hostname',k:'hostname',c:'ac'},{l:'Marka',k:'brand',c:''},{l:'Model',k:'model',c:'or'},
    {l:'Yazılım Sürümü',k:'software_version',c:'bl'},{l:'Seri No',k:'serial_no',c:''},
    {l:'Uptime',k:'uptime',c:''},{l:'Build',k:'build',c:''},{l:'Edition',k:'edition',c:''},
    {l:'Platform',k:'platform',c:''},{l:'Patch',k:'patch',c:''},{l:'HA Modu',k:'ha_mode',c:''},
    {l:'Son Reboot',k:'last_reboot_reason',c:''},{l:'BIOS',k:'bios_version',c:''},
    {l:'Ürün',k:'product',c:''},
  ].filter(f=>col[f.k]!=null&&col[f.k]!=='');
  if(mainFields.length)
    html+=`<div class="inv-grid">`+mainFields.map(f=>`<div class="icard"><div class="il">${f.l}</div><div class="iv ${f.c}">${esc(String(col[f.k]))}</div></div>`).join('')+`</div>`;
  // Stack members (Cisco)
  if(col.stack_members?.length){
    html+=`<div class="ss" style="font-size:12px;margin-top:10px">🔀 Stack Üyeleri (${col.stack_members.length})</div>`;
    html+=col.stack_members.map(m=>`<div class="stack-row"><span class="tag tb">Switch ${esc(m.member||'?')}</span><span style="flex:1"><b>${esc(m.model||'?')}</b></span><code style="color:var(--text2);font-size:11px">${esc(m.serial_number||'—')}</code></div>`).join('');
  }
  // Slot serials (Huawei)
  const slots=Object.keys(col).filter(k=>k.startsWith('serial_slot_'));
  if(slots.length){
    html+=`<div class="ss" style="font-size:12px;margin-top:10px">🗄️ Slot Seri Numaraları</div>`;
    html+=`<div class="fl">`+slots.map(k=>`<div class="fi"><span class="fn">${esc(k.replace('serial_',''))}</span><code style="color:var(--text2)">${esc(col[k]||'—')}</code></div>`).join('')+`</div>`;
  }
  // HA members (FortiGate HA cluster)
  if(col.ha_members?.length){
    html+=`<div class="ss" style="font-size:12px;margin-top:10px">🔄 HA Küme Üyeleri (${col.ha_members.length+1})</div>`;
    // Add this device as primary/master
    html+=`<div class="stack-row"><span class="tag tg">Bu cihaz</span><span style="flex:1"><b>${esc(col.hostname||'?')}</b></span><code style="color:var(--text2);font-size:11px">${esc(col.serial_no||'—')}</code><span class="tag ${col.ha_role?'to':'tgr'}">${esc(col.ha_role||'master')}</span></div>`;
    col.ha_members.forEach(m=>{
      html+=`<div class="stack-row"><span class="tag tb">${esc(m.role||'slave')}</span><span style="flex:1"><b>${esc(m.hostname||'—')}</b></span><code style="color:var(--text2);font-size:11px">${esc(m.serial||'—')}</code></div>`;
    });
  }
  // Extra fields
  const shown=new Set([...mainFields.map(f=>f.k),'stack_members','ha_members','device','ip','source_file','collected_at','neighbors','portchannels','neighbors_collected',...slots]);
  const extra=Object.entries(col).filter(([k])=>!shown.has(k)&&col[k]!=null&&col[k]!=='');
  if(extra.length){
    html+=`<div class="ss" style="font-size:12px;margin-top:10px">📝 Diğer</div>`;
    html+=`<div class="fl">`+extra.map(([k,v])=>`<div class="fi"><span class="fn">${esc(k)}</span><span style="font-size:11px;color:var(--text2);word-break:break-all">${esc(String(v))}</span></div>`).join('')+`</div>`;
  }
  el.innerHTML=html||`<div class="empty"><p>Veri yok</p></div>`;
}

function renderDTabNb(col){
  const el=document.getElementById('dtab-nb');
  const nbs=col?.neighbors||[];
  if(!nbs.length){
    el.innerHTML=`<div class="empty"><div class="ei">🔗</div><p>Komşuluk verisi yok.</p><p style="margin-top:6px;font-size:11px">🔗 "Komşuluk" butonuyla CDP/LLDP toplayabilirsiniz.</p></div>`;
    return;
  }
  const ts=col.neighbors_collected?`<div style="color:var(--text3);font-size:10px;margin-bottom:10px">Son güncelleme: ${esc(col.neighbors_collected)}</div>`:'';
  let html=ts+`<div style="overflow-x:auto"><table class="nb-table">
    <thead><tr><th>Uzak Cihaz</th><th>Lokal Port</th><th>Port-Channel</th><th>Uzak Port</th><th>VLAN'lar</th><th>Protokol</th></tr></thead>
    <tbody>`;
  nbs.forEach(nb=>{
    const pcBadge=nb.portchannel?`<span class="tag tp">${esc(nb.portchannel)}</span>`:'—';
    const vlanStr=(nb.vlans||[]).length?nb.vlans.slice(0,15).join(', ')+(nb.vlans.length>15?'…':''):'—';
    html+=`<tr>
      <td><b>${esc(nb.remote_host)}</b>${nb.platform?` <span class="tag tgr" style="margin-left:4px">${esc(nb.platform)}</span>`:''}</td>
      <td><code style="color:var(--accent2)">${esc(nb.local_port||'—')}</code></td>
      <td>${pcBadge}</td>
      <td><code style="color:var(--text2)">${esc(nb.remote_port||'—')}</code></td>
      <td style="font-size:10px;color:var(--text2)">${esc(vlanStr)}</td>
      <td><span class="tag ${nb.protocol==='CDP'?'to':'tb'}">${esc(nb.protocol||'?')}</span></td>
    </tr>`;
  });
  html+=`</tbody></table></div>`;
  // Port-channel summary
  const pcs=col.portchannels||{};
  if(Object.keys(pcs).length){
    html+=`<div class="ss" style="font-size:12px;margin-top:12px">⚙️ Port-Channel Özeti</div>`;
    html+=`<div class="fl">`;
    Object.entries(pcs).forEach(([name,pc])=>{
      const vlStr=(pc.vlans||[]).length?`<br><span style="font-size:10px;color:var(--text3)">VLAN: ${pc.vlans.slice(0,15).join(', ')}</span>`:'';
      html+=`<div class="fi"><span class="fn" style="min-width:90px"><span class="tag tp">${esc(name)}</span></span><div><span style="color:var(--text2);font-size:11px">${(pc.members||[]).join(', ')||'—'}</span>${vlStr}</div></div>`;
    });
    html+=`</div>`;
  }
  el.innerHTML=html;
}

// Global backup path registry - avoids path encoding issues in onclick
const _bkPaths = {};
function _bkKey(devIdx, fileIdx){ return `${devIdx}_${fileIdx}`; }

function renderDTabBk(backups,d){
  const el=document.getElementById('dtab-bk');
  if(!backups?.length){
    el.innerHTML=`<div class="empty"><div class="ei">💾</div><p>${esc(d.name)} için backup bulunamadı.</p></div>`;
    return;
  }
  const txtFiles=backups.filter(b=>b.name.endsWith('.txt')||b.name.endsWith('.conf'));
  const diffBtn=txtFiles.length>=2
    ?`<button class="btn btn-b btn-sm" style="margin-bottom:10px" onclick="openDiffSel()">🔀 Karşılaştır (${txtFiles.length} dosya)</button>`:'';
  const byDate={};
  let gIdx=0;
  backups.forEach(b=>{
    b._gIdx=gIdx;
    _bkPaths[_bkKey(_curDevIdx,gIdx)]={date:b.date||'',name:b.name||''};
    gIdx++;
    byDate[b.date]=byDate[b.date]||[];byDate[b.date].push(b);
  });
  let html=diffBtn+`<div class="card" style="padding:0;overflow:hidden">`;
  Object.entries(byDate).sort((a,b)=>b[0].localeCompare(a[0])).forEach(([date,files])=>{
    html+=`<div style="padding:6px 12px 3px;background:var(--bg3);border-bottom:1px solid var(--border);font-size:10px;color:var(--text2);text-transform:uppercase;letter-spacing:1px">📅 ${date} — ${files.length} dosya</div>`;
    files.forEach(f=>{
      const ico=f.name.endsWith('.ucs')?'💿':f.name.endsWith('.conf')?'📄':'📃';
      const canOpen=f.name.endsWith('.txt')||f.name.endsWith('.conf');
      const gi=f._gIdx??0;
      html+=`<div class="bk-row${canOpen?' clickable':''}" ${canOpen?`onclick="openConfByIdx(${_curDevIdx},${gi},'${esc(f.name)}')"`:''}>
        <span style="font-size:16px">${ico}</span>
        <code style="flex:1;font-size:11px;color:${canOpen?'var(--accent2)':'var(--text)'}">${esc(f.name)}</code>
        <span style="color:var(--text3);font-size:11px">${fmtSz(f.size)}</span>
        <button class="btn btn-b btn-xs" style="flex-shrink:0;margin-left:4px" onclick="event.stopPropagation();dlBackup(${_curDevIdx},${gi},'${esc(f.name)}')" title="İndir">⬇️</button>
        ${canOpen?'<span style="color:var(--text2);font-size:10px">→ aç</span>':''}
      </div>`;
    });
  });
  html+=`</div>`;
  el.innerHTML=html;
}
function openConfByIdx(devIdx,fileIdx,name){
  const bk=_bkPaths[_bkKey(devIdx,fileIdx)];
  if(!bk){toast('Dosya yolu bulunamadı','err');return;}
  openConf('',bk.name||name,bk.date||'');
}
// note toggle / save
function toggleNoteEdit(idx,cancel){
  const view=document.getElementById('note-view-'+idx);
  const edit=document.getElementById('note-edit-'+idx);
  const ta=document.getElementById('note-ta-'+idx);
  if(!view||!edit)return;
  const show=edit.style.display==='none';
  if(cancel){edit.style.display='none';view.style.display='';return;}
  if(show){edit.style.display='block';view.style.display='none';if(ta)ta.focus();}
  else{edit.style.display='none';view.style.display='';}
}
async function saveNote(idx){
  const ta=document.getElementById('note-ta-'+idx);if(!ta)return;
  const notes=ta.value;
  try{
    const d={..._iD[idx],notes};
    await api('PUT',`/api/inventory/${idx}`,d);
    _iD[idx].notes=notes;
    const view=document.getElementById('note-view-'+idx);
    if(view)view.textContent=notes||'—';
    toggleNoteEdit(idx,true);
    toast('Not kaydedildi','ok');
  }catch(e){toast(e.message,'err');}
}

// single collect
async function collectSingle(){
  const btn=document.getElementById('mid-col-btn');btn.disabled=true;
  document.getElementById('mid-cbadge').innerHTML='<span class="tag tb">⏳</span>';
  try{
    const r=await api('POST',`/api/device/${_curDevIdx}/collect`);
    pollJob(r.job_id,null,'mid-cbadge',async()=>{
      btn.disabled=false;
      const upd=await api('GET',`/api/device/${_curDevIdx}/detail`);
      renderDTabHw(upd.collector,_iD[_curDevIdx]);
      const hn=upd.collector?.hostname;
      if(hn&&hn.toLowerCase()!==_iD[_curDevIdx].name.toLowerCase()){
        document.getElementById('mid-hmm').innerHTML=`<div class="hmm-banner">⚠️ Kayıtlı: <b>${esc(_iD[_curDevIdx].name)}</b> | Hostname: <b>${esc(hn)}</b></div>`;
      }else document.getElementById('mid-hmm').innerHTML='';
      toast('Envanter güncellendi','ok');
    });
  }catch(e){toast(e.message,'err');btn.disabled=false;document.getElementById('mid-cbadge').innerHTML='';}
}

// single backup
async function backupSingle(){
  const btn=document.getElementById('mid-bk-btn');btn.disabled=true;
  document.getElementById('mid-cbadge').innerHTML='<span class="tag tb">⏳ Backup…</span>';
  try{
    const r=await api('POST',`/api/device/${_curDevIdx}/backup`);
    pollJob(r.job_id,null,'mid-cbadge',async()=>{
      btn.disabled=false;
      // Refresh backups tab
      const upd=await api('GET',`/api/device/${_curDevIdx}/detail`);
      _devBkFiles=upd.backups||[];
      renderDTabBk(upd.backups,_iD[_curDevIdx]);
      const bCnt=upd.backups?.length||0;
      if(bCnt)document.getElementById('bk-cnt').innerHTML=`<span class="tag tb" style="padding:1px 5px;font-size:10px">${bCnt}</span>`;
      toast('Backup tamamlandı','ok');
    });
  }catch(e){toast(e.message,'err');btn.disabled=false;document.getElementById('mid-cbadge').innerHTML='';}
}

// ════════════════════════════════════════════════════
// SSH TERMINAL  (SSE + POST, platform bağımsız)
// ════════════════════════════════════════════════════
let _sshSid      = null;   // session id
let _sshEvt      = null;   // EventSource
let _sshLogName  = null;   // log file name
let _sshClosed   = false;

function sshWrite(text, color){
  const out = document.getElementById('ssh-output');
  if(!out) return;
  const span = document.createElement('span');
  if(color) span.style.color = color;
  span.textContent = text;
  out.appendChild(span);
  out.scrollTop = out.scrollHeight;
}
function sshClear(){ const o=document.getElementById('ssh-output'); if(o) o.innerHTML=''; }
function sshSetStatus(msg, color){
  const el=document.getElementById('ssh-status');
  if(el){ el.textContent=msg; el.style.color=color||'var(--text2)'; }
}

async function sshConnect(){
  if(_sshSid) sshDisconnect();
  sshClear();
  _sshClosed = false;
  _sshLogName = null;
  sshSetStatus('Bağlanılıyor…','var(--accent)');
  document.getElementById('ssh-conn-btn').disabled = true;
  document.getElementById('ssh-disc-btn').style.display = 'none';
  document.getElementById('ssh-log-dl-btn').style.display = 'none';

  try{
    const r = await api('POST', `/api/ssh/${_curDevIdx}/start`);
    _sshSid = r.sid;
  }catch(e){
    sshSetStatus('Başlatılamadı: '+e.message, 'var(--danger)');
    document.getElementById('ssh-conn-btn').disabled = false;
    return;
  }

  // SSE stream
  _sshEvt = new EventSource(`/api/ssh/${_sshSid}/stream`);
  _sshEvt.onmessage = (ev) => {
    if(!ev.data || ev.data === '{}') return;  // heartbeat
    let msg;
    try{ msg = JSON.parse(ev.data); }catch(_){ return; }
    if(msg.type === 'data'){
      sshAppendAnsi(msg.d);
    } else if(msg.type === 'connected'){
      sshSetStatus(msg.msg, 'var(--ok)');
      document.getElementById('ssh-disc-btn').style.display = '';
      document.getElementById('ssh-conn-btn').disabled = false;
      if(msg.log) _sshLogName = msg.log;
      document.getElementById('ssh-input-trap').focus();
    } else if(msg.type === 'status'){
      sshWrite(msg.msg + '\r\n', '#58a6ff');
    } else if(msg.type === 'error'){
      sshWrite('\n[HATA] ' + msg.msg + '\n', 'var(--danger)');
      sshSetStatus('Hata', 'var(--danger)');
      _sshSid = null; _sshEvt?.close(); _sshEvt = null;
      document.getElementById('ssh-conn-btn').disabled = false;
    } else if(msg.type === 'disconnected'){
      sshWrite('\r\n[Bağlantı kapandı]\r\n', '#58a6ff');
      sshSetStatus('Bağlantı kesildi', 'var(--text3)');
      if(msg.log) _sshLogName = msg.log;
      if(_sshLogName) document.getElementById('ssh-log-dl-btn').style.display = '';
      document.getElementById('ssh-conn-btn').disabled = false;
      document.getElementById('ssh-disc-btn').style.display = 'none';
      _sshEvt?.close(); _sshEvt = null; _sshSid = null;
    }
  };
  _sshEvt.onerror = () => {
    if(_sshClosed) return;
    sshSetStatus('SSE bağlantısı kesildi','var(--danger)');
    document.getElementById('ssh-conn-btn').disabled = false;
    _sshEvt?.close(); _sshEvt = null;
  };
}

function sshDisconnect(){
  _sshClosed = true;
  if(_sshSid){
    fetch(`/api/ssh/${_sshSid}/close`, {method:'POST'}).catch(()=>{});
    _sshSid = null;
  }
  _sshEvt?.close(); _sshEvt = null;
  sshSetStatus('Bağlantı kesildi','var(--text3)');
  document.getElementById('ssh-conn-btn').disabled = false;
  document.getElementById('ssh-disc-btn').style.display = 'none';
  if(_sshLogName) document.getElementById('ssh-log-dl-btn').style.display = '';
}

function sshSend(text){
  if(!_sshSid) return;
  fetch(`/api/ssh/${_sshSid}/input`, {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({d: text})
  }).catch(()=>{});
}

function sshKeyDown(e){
  if(!_sshSid) return;
  const map = {
    'Enter':'\r','Backspace':'\x7f','Tab':'\t',
    'ArrowUp':'\x1b[A','ArrowDown':'\x1b[B','ArrowRight':'\x1b[C','ArrowLeft':'\x1b[D',
    'Home':'\x1b[H','End':'\x1b[F','Delete':'\x1b[3~',
    'PageUp':'\x1b[5~','PageDown':'\x1b[6~','Escape':'\x1b',
    'F1':'\x1bOP','F2':'\x1bOQ','F3':'\x1bOR','F4':'\x1bOS',
  };
  if(e.ctrlKey && !e.altKey){
    const c = e.key.toLowerCase();
    if(c >= 'a' && c <= 'z'){ e.preventDefault(); sshSend(String.fromCharCode(c.charCodeAt(0)-96)); return; }
    if(c === '['){ e.preventDefault(); sshSend('\x1b'); return; }
  }
  if(map[e.key]){ e.preventDefault(); sshSend(map[e.key]); }
}

function sshInput(e){
  if(!_sshSid) return;
  const val = e.target.value;
  if(val){ sshSend(val); e.target.value = ''; }
}

function sshAppendAnsi(text){
  const out = document.getElementById('ssh-output');
  if(!out) return;
  const colorMap = {
    '30':'#6e7681','31':'#ff7b72','32':'#3fb950','33':'#d29922',
    '34':'#58a6ff','35':'#bc8cff','36':'#39c5cf','37':'#e6edf3',
    '90':'#6e7681','91':'#ffa198','92':'#56d364','93':'#e3b341',
    '94':'#79c0ff','95':'#d2a8ff','96':'#56d4dd','97':'#ffffff',
  };
  const parts = text.split(/(\x1b\[[0-9;]*m|\x1b\[[0-9;]*[ABCDJKH]|\x1b\[[?][0-9;]*[hl]|\x1b\([A-Z]|\x1b[=>M]|\r)/g);
  let curStyle = {};
  for(const part of parts){
    if(!part || part === '\r') continue;
    const ansiM = part.match(/^\x1b\[([0-9;]*)m$/);
    if(ansiM){
      const codes = (ansiM[1]||'0').split(';');
      for(const code of codes){
        if(!code||code==='0') curStyle={};
        else if(code==='1') curStyle.fontWeight='bold';
        else if(code==='3') curStyle.fontStyle='italic';
        else if(colorMap[code]) curStyle.color=colorMap[code];
      }
      continue;
    }
    if(part.startsWith('\x1b')) continue;
    const span = document.createElement('span');
    span.textContent = part;
    if(curStyle.color) span.style.color = curStyle.color;
    if(curStyle.fontWeight) span.style.fontWeight = curStyle.fontWeight;
    if(curStyle.fontStyle) span.style.fontStyle = curStyle.fontStyle;
    out.appendChild(span);
  }
  out.scrollTop = out.scrollHeight;
}

function sshDownloadLog(){
  if(!_sshLogName){ toast('Log dosyası yok','err'); return; }
  const a=document.createElement('a');
  a.href='/api/ssh-logs/download?name='+encodeURIComponent(_sshLogName);
  a.download=_sshLogName; a.click();
}

function goSshLogs(){ gp('ssh-logs'); }

function onSshTabOpen(){
  _sshClosed = false;
  setTimeout(()=>document.getElementById('ssh-input-trap')?.focus(), 50);
}

async function loadSshLogs(){
  const el=document.getElementById('ssh-logs-list'); if(!el) return;
  el.innerHTML='<div class="empty"><div class="ei">⏳</div></div>';
  try{
    const r=await api('GET','/api/ssh-logs');
    if(!r.logs?.length){
      el.innerHTML='<div class="empty"><div class="ei">📋</div><p>Kayıtlı SSH oturumu yok.</p></div>';
      return;
    }
    // Store paths globally for viewer
    window._sshLogPaths = {};
    r.logs.forEach((l,i)=>{ window._sshLogPaths[i]=l.path; });
    el.innerHTML=r.logs.map((l,i)=>`
      <div class="bk-row clickable" onclick="openSshLog(${i},'${esc(l.name)}')">
        <span style="font-size:16px">🖥️</span>
        <div style="flex:1;min-width:0">
          <code style="color:var(--accent2);font-size:11px">${esc(l.name)}</code><br>
          <span style="color:var(--text3);font-size:10px">${esc(l.date)}</span>
        </div>
        <span style="color:var(--text3);font-size:11px;flex-shrink:0">${fmtSz(l.size)}</span>
        <div style="display:flex;gap:5px;flex-shrink:0" onclick="event.stopPropagation()">
          <button class="btn btn-b btn-xs" onclick="openSshLog(${i},'${esc(l.name)}')">👁 Aç</button>
          <a class="btn btn-p btn-xs" href="/api/ssh-logs/download?name=${enc(l.name)}" download="${esc(l.name)}">⬇️ İndir</a>
        </div>
      </div>`).join('');
  }catch(e){ el.innerHTML=`<div class="empty"><p style="color:var(--danger)">${esc(e.message)}</p></div>`; }
}

function openSshLog(idx, name){
  const path = window._sshLogPaths?.[idx];
  if(!path){ toast('Dosya yolu bulunamadi','err'); return; }
  document.getElementById('mcv-title').textContent = name;
  document.getElementById('mcv-srch').value = '';
  document.getElementById('mcv-info').textContent = '';
  const _dlb = document.getElementById('mcv-dl-btn');
  if(_dlb){
    _dlb.style.display = '';
    _dlb.onclick = ()=>{ const a=document.createElement('a'); a.href='/api/ssh-logs/download?name='+encodeURIComponent(name); a.download=name; a.click(); };
  }
  document.getElementById('mcv-body').innerHTML='<div class="empty"><div class="ei">⏳</div><p>Yukleniyor</p></div>';
  om('mcv');
  api('GET','/api/backup/file?path='+encodeURIComponent(path))
    .then(d=>{
      const lines=d.content.split('\n');
      document.getElementById('mcv-body').innerHTML=lines.map((l,i)=>
        `<div class="conf-line"><span class="conf-ln">${i+1}</span><span class="conf-txt">${esc(l)}</span></div>`
      ).join('');
      document.getElementById('mcv-info').textContent=`${lines.length} satir`;
    })
    .catch(e=>{ document.getElementById('mcv-body').innerHTML=`<div class="empty"><p style="color:var(--danger)">${esc(e.message)}</p></div>`; });
}

function dlBackup(devIdx, fileIdx, name){
  const bk=_bkPaths[_bkKey(devIdx,fileIdx)];
  if(!bk){ toast('Dosya yolu bulunamadı','err'); return; }
  dlBackupFile(bk.date||'',bk.name||name);
}


// neighbors collect
async function collectNeighbors(){
  const btn=document.getElementById('mid-nb-btn');btn.disabled=true;
  document.getElementById('nb-cnt').innerHTML='<span class="tag tb" style="padding:1px 5px;font-size:10px">⏳</span>';
  try{
    const ip=_iD[_curDevIdx]?.ip;
    const r=await api('POST',`/api/device-details/${enc(ip)}/neighbors`);
    pollJob(r.job_id,null,'nb-cnt',async()=>{
      btn.disabled=false;
      const upd=await api('GET',`/api/device/${_curDevIdx}/detail`);
      renderDTabNb(upd.collector);
      swDTab('nb');
      const cnt=upd.collector?.neighbors?.length||0;
      document.getElementById('nb-cnt').innerHTML=cnt?`<span class="tag tg" style="padding:1px 5px;font-size:10px">${cnt}</span>`:'';
      toast(`${cnt} komşu bulundu`,'ok');
    });
  }catch(e){toast(e.message,'err');btn.disabled=false;}
}

// ════════════════════════════════════════════════════
// CONFIG VIEWER
// ════════════════════════════════════════════════════
async function openConf(path,name,date){
  // path eski uyumluluk için, date+name tercih edilir
  document.getElementById('mcv-title').textContent=name;
  document.getElementById('mcv-srch').value='';
  document.getElementById('mcv-info').textContent='';
  const _dlb=document.getElementById('mcv-dl-btn');
  if(_dlb){
    _dlb.style.display='';
    _dlb.onclick=function(){ dlBackupFile(date||'',name); };
  }
  document.getElementById('mcv-body').innerHTML='<div class="empty"><div class="ei">⏳</div><p>Yükleniyor…</p></div>';
  om('mcv');
  // URL: date+name varsa onları kullan, yoksa path'i dene (geriye uyumluluk)
  let url;
  if(name && (date||path)){
    url='/api/backup/file?name='+enc(name)+(date?'&date='+enc(date):'');
  } else {
    url='/api/backup/file?path='+enc(path||name);
  }
  api('GET',url)
    .then(d=>{
      const lines=d.content.split('\n');
      document.getElementById('mcv-body').innerHTML=lines.map((l,i)=>
        `<div class="conf-line"><span class="conf-ln">${i+1}</span><span class="conf-txt">${esc(l)}</span></div>`
      ).join('');
      document.getElementById('mcv-info').textContent=`${lines.length} satır`;
    })
    .catch(e=>{document.getElementById('mcv-body').innerHTML=`<div class="empty"><p style="color:var(--danger)">${esc(e.message)}</p></div>`;});
}
function confSearch(){
  const q=document.getElementById('mcv-srch').value.toLowerCase();
  const lines=document.querySelectorAll('#mcv-body .conf-line');
  let cnt=0;
  lines.forEach(el=>{
    const txt=el.querySelector('.conf-txt').textContent.toLowerCase();
    const match=q&&txt.includes(q);
    el.style.display=q&&!match?'none':'';
    el.classList.toggle('hl',match);
    if(match)cnt++;
  });
  document.getElementById('mcv-info').textContent=q?`${cnt} eşleşme`:`${lines.length} satır`;
}

// ════════════════════════════════════════════════════
// DIFF
// ════════════════════════════════════════════════════
function openDiffSel(){
  const txtFiles=_devBkFiles.filter(b=>b.name.endsWith('.txt')||b.name.endsWith('.conf'));
  _dsSelA=null;_dsSelB=null;
  document.getElementById('ds-a-name').textContent='—';document.getElementById('ds-b-name').textContent='—';
  document.getElementById('ds-go').disabled=true;
  const mkList=(containerId,side)=>{
    const el=document.getElementById(containerId);
    el.innerHTML=txtFiles.map((f,i)=>`<div class="dsel-item" onclick="selectDiffFile(${i},'${side}','${containerId}')" data-bidx="${f._gIdx??i}" data-name="${esc(f.name)}">
      <span style="color:var(--text3);font-size:10px">${f.date}</span> ${esc(f.name)}
    </div>`).join('');
  };
  mkList('ds-list-a','a');mkList('ds-list-b','b');
  om('mds');
}
function selectDiffFile(idx,side,containerId){
  const items=document.querySelectorAll(`#${containerId} .dsel-item`);
  items.forEach((el,i)=>{el.classList.remove(side==='a'?'sel-a':'sel-b');if(i===idx)el.classList.add(side==='a'?'sel-a':'sel-b');});
  const el=items[idx];
  const bk=_bkPaths[_bkKey(_curDevIdx,parseInt(el.dataset.bidx??idx))];
  const ref=bk?JSON.stringify(bk):(el.dataset.path||'');
  if(side==='a'){_dsSelA=ref;document.getElementById('ds-a-name').textContent=el.dataset.name;}
  else{_dsSelB=ref;document.getElementById('ds-b-name').textContent=el.dataset.name;}
  document.getElementById('ds-go').disabled=!(_dsSelA&&_dsSelB);
}
async function runDiff(){
  if(!_dsSelA||!_dsSelB)return;
  document.getElementById('dv-a-name').textContent=document.getElementById('ds-a-name').textContent;
  document.getElementById('dv-b-name').textContent=document.getElementById('ds-b-name').textContent;
  document.getElementById('dv-body').innerHTML='<div class="empty"><div class="ei">⏳</div><p>Karşılaştırılıyor…</p></div>';
  document.getElementById('dv-summary').innerHTML='';
  cm('mds');om('mdv');
  try{
    // _dsSelA/B = JSON string {date,name} veya eski path string
    let _ra=_dsSelA,_rb=_dsSelB;
    try{const _pa=JSON.parse(_dsSelA);_ra=(_pa.date||'')+':'+(_pa.name||'');} catch(e){}
    try{const _pb=JSON.parse(_dsSelB);_rb=(_pb.date||'')+':'+(_pb.name||'');} catch(e){}
    const d=await api('GET',`/api/backup/diff?a=${enc(_ra)}&b=${enc(_rb)}`);
    if(!d.diff.length){document.getElementById('dv-body').innerHTML='<div class="empty"><div class="ei">✅</div><p>Dosyalar aynı</p></div>';return;}
    const adds=d.diff.filter(l=>l.startsWith('+')&&!l.startsWith('+++')).length;
    const rems=d.diff.filter(l=>l.startsWith('-')&&!l.startsWith('---')).length;
    document.getElementById('dv-summary').innerHTML=`<span class="tag tg">+${adds}</span> <span class="tag tr">-${rems}</span>`;
    document.getElementById('dv-body').innerHTML=d.diff.map(l=>{
      const cls=l.startsWith('+')&&!l.startsWith('+++')?'add':l.startsWith('-')&&!l.startsWith('---')?'rem':l.startsWith('@')?'hdr':'ctx';
      return `<div class="dl ${cls}">${esc(l)}</div>`;
    }).join('');
  }catch(e){document.getElementById('dv-body').innerHTML=`<div class="empty"><p style="color:var(--danger)">${esc(e.message)}</p></div>`;}
}

// ════════════════════════════════════════════════════
// EXCLUDE
// ════════════════════════════════════════════════════
async function loadExclude(){_eD=await api('GET','/api/exclude');renderExcl();}
function renderExcl(){
  const tb=document.getElementById('etb');
  if(!_eD.length){tb.innerHTML=`<tr><td colspan="5"><div class="empty"><div class="ei">🚫</div><p>Liste boş</p></div></td></tr>`;return;}
  tb.innerHTML=_eD.map((e,i)=>`<tr><td style="color:var(--text2)">${i+1}</td><td><code style="color:var(--accent3)">${esc(e.ip)}</code></td><td style="color:var(--text2)">${esc(e.description||'—')}</td><td style="color:var(--text3);font-size:11px">${esc(e.added_at||'')}</td><td class="adm"><button class="btn btn-d btn-i btn-xs" onclick="delExcl(${i})">🗑</button></td></tr>`).join('');
  document.querySelectorAll('.adm').forEach(el=>el.style.display=_role==='admin'?'':'none');
}
function openAddExcl(){document.getElementById('ae-ip').value='';document.getElementById('ae-desc').value='';om('mae');}
async function addExclude(){const ip=document.getElementById('ae-ip').value.trim(),desc=document.getElementById('ae-desc').value.trim();if(!ip){toast('IP gerekli','err');return;}try{await api('POST','/api/exclude',{ip,description:desc});toast('Eklendi','ok');cm('mae');loadExclude();}catch(e){toast(e.message,'err');}}
async function delExcl(idx){if(!confirm('Kaldırılsın mı?'))return;try{await api('DELETE',`/api/exclude/${idx}`);toast('Silindi','ok');loadExclude();}catch(e){toast(e.message,'err');}}

// ════════════════════════════════════════════════════
// BACKUP
// ════════════════════════════════════════════════════
function toggleBkTag(){document.getElementById('bk-tag-row').style.display=document.getElementById('bk-mode').value==='tag'?'block':'none';}
async function startBackup(){
  const mode=document.getElementById('bk-mode').value,tag=document.getElementById('bk-tag').value.trim();
  document.getElementById('bk-log').innerHTML='';setBadge('bk-badge','running');
  try{const d=await api('POST','/api/backup/start',{mode,tag});toast(`${d.device_count} cihaz yedekleniyor…`,'info');pollJob(d.job_id,'bk-log','bk-badge',()=>{loadBackups();loadStats();});}
  catch(e){toast(e.message,'err');setBadge('bk-badge','error');}
}
async function loadBackups(){
  const data=await api('GET','/api/backup/list');const el=document.getElementById('bk-list');
  if(!data.length){el.innerHTML='<div class="empty"><div class="ei">💾</div><p>Henüz backup yok</p></div>';return;}
  // Toplam dosya sayısı
  const totalFiles=data.reduce((s,d)=>s+d.count,0);
  el.innerHTML=`<div style="display:flex;justify-content:flex-end;margin-bottom:8px;gap:6px">
    <span style="font-size:11px;color:var(--text3);align-self:center">${totalFiles} backup dosyası</span>
    <button class="btn btn-s btn-sm" onclick="dlAllBackups()" title="Tüm backupları ZIP olarak indir">⬇️ Tümünü İndir</button>
  </div>`
  +data.map(day=>`<div class="card" style="margin-bottom:10px">
    <div class="chdr">
      <div class="ct">📅 ${day.date}</div>
      <div style="display:flex;gap:6px;align-items:center">
        <span class="tag tg">${day.count} dosya</span>
        <button class="btn btn-s btn-xs" onclick="dlDayBackups('${esc(day.date)}')" title="Bu günün backuplarını indir">⬇️ Günü İndir</button>
      </div>
    </div>
    <div class="tw"><table><thead><tr><th>Dosya</th><th>Boyut</th><th style="width:60px"></th></tr></thead>
    <tbody>${day.files.map(f=>{
      const canOpen=f.name.endsWith('.txt')||f.name.endsWith('.conf')||f.name.endsWith('.cfg')||f.name.endsWith('.bak');
      const viewBtn=canOpen?`<code style="cursor:pointer;color:var(--accent2)" onclick="openConf('','${esc(f.name)}','${esc(day.date)}')">${esc(f.name)}</code>`
                           :`<code style="color:var(--text)">${esc(f.name)}</code>`;
      const dlBtn=`<button class="btn btn-s btn-xs" onclick="dlBackupFile('${esc(day.date)}','${esc(f.name)}')" title="İndir">⬇</button>`;
      return `<tr><td>${viewBtn}</td><td style="color:var(--text2)">${fmtSz(f.size)}</td><td>${dlBtn}</td></tr>`;
    }).join('')}</tbody></table></div></div>`).join('');
}

function dlAllBackups(){
  const a=document.createElement('a');
  a.href='/api/backup/download-all';
  a.download='backups_all.zip';
  document.body.appendChild(a);a.click();a.remove();
}
function dlDayBackups(date){
  const a=document.createElement('a');
  a.href='/api/backup/download-all?date='+encodeURIComponent(date);
  a.download='backups_'+date+'.zip';
  document.body.appendChild(a);a.click();a.remove();
}
function dlBackupFile(date,name){
  const a=document.createElement('a');
  a.href='/api/backup/download?date='+encodeURIComponent(date)+'&name='+encodeURIComponent(name);
  a.download=name;
  document.body.appendChild(a);a.click();a.remove();
}

// ════════════════════════════════════════════════════
// SCAN
// ════════════════════════════════════════════════════
async function startScan(){
  const t=document.getElementById('sc-tgt').value.trim();if(!t){toast('Hedef gerekli','err');return;}
  document.getElementById('sc-log').innerHTML='';document.getElementById('sc-results').innerHTML='';setBadge('sc-badge','running');
  try{const d=await api('POST','/api/scan/start',{targets:t});toast(`${d.target_count} IP taranıyor…`,'info');
    pollJob(d.job_id,'sc-log','sc-badge',j=>{renderScanRes(j);loadInventory();loadStats();});}
  catch(e){toast(e.message,'err');setBadge('sc-badge','error');}
}
function renderScanRes(job){
  if(!job.result?.devices?.length)return;
  document.getElementById('sc-results').innerHTML=`<div class="ss">🔎 Bulunan Cihazlar (${job.result.devices.length})</div>`+
    job.result.devices.map(d=>`<div style="background:var(--bg3);border:1px solid var(--border);border-radius:var(--r);padding:10px 14px;margin-bottom:6px;display:grid;grid-template-columns:130px 1fr 90px;gap:10px;align-items:center;font-size:12px">
      <div><code style="color:var(--accent2)">${esc(d.ip)}</code><br><span style="font-size:10px;color:var(--text3)">${esc(d.mac)}</span></div>
      <div><span class="tag tgr">${esc(d.vendor||'?')}</span>${d.ssh?` <span class="tag tg">${esc(d.type||'?')}</span>`:''}<br><span style="font-size:10px;color:var(--text2)">Port: ${(d.ports||[]).join(', ')||'—'}</span></div>
      <div style="text-align:right">${d.added?'<span class="tag tg">✅ Eklendi</span>':'<span class="tag tgr">—</span>'}</div>
    </div>`).join('');
}

// ════════════════════════════════════════════════════
// COLLECTOR
// ════════════════════════════════════════════════════
async function startCollector(){
  const tag=document.getElementById('col-tag').value.trim()||'all';
  document.getElementById('col-log').innerHTML='';setBadge('col-badge','running');
  try{const d=await api('POST','/api/collector/start',{tag});toast(`${d.device_count} cihaz işlenecek…`,'info');
    pollJob(d.job_id,'col-log','col-badge',(j)=>{
      loadColOutputs();
      const diffs=(j.result||{}).hostname_diffs||[];
      if(diffs.length) _showHostnameDiffModal(diffs);
    });}
  catch(e){toast(e.message,'err');setBadge('col-badge','error');}
}
// ── Hostname Diff Modal ─────────────────────────────────
let _pendingDiffs = [];

function _showHostnameDiffModal(diffs){
  _pendingDiffs = diffs;
  const rows = diffs.map((d,i)=>[
    '<tr>',
      '<td><label style="cursor:pointer">',
        '<input type="checkbox" checked data-i="'+i+'" style="margin-right:6px">',
        '<b style="color:var(--accent)">'+esc(d.inv_name)+'</b>',
      '</label></td>',
      '<td style="color:var(--text3)">&rarr;</td>',
      '<td><b style="color:#22c55e">'+esc(d.hostname)+'</b></td>',
    '</tr>'
  ].join('')).join('');
  const body = [
    '<p style="margin-bottom:12px;color:var(--text2)">',
      'Aşağıdaki cihazların kayıt adı, cihazdan okunan hostname ile farklı.<br>',
      'Güncellemek istediklerinizi seçin:</p>',
    '<div class="tw" style="max-height:300px;overflow-y:auto">',
      '<table><thead><tr>',
        '<th>Mevcut Kayıt Adı</th><th></th><th>Cihaz Hostname (yeni ad)</th>',
      '</tr></thead><tbody>'+rows+'</tbody></table>',
    '</div>',
    '<div style="display:flex;gap:8px;margin-top:14px;justify-content:flex-end">',
      '<button class="btn btn-s" onclick="cm(this.dataset.m)" data-m="hdiff-modal">İptal</button>',
      '<button class="btn btn-p" onclick="_applyHostnameDiffs()">&#x2705; Seçilileri Güncelle</button>',
    '</div>'
  ].join('');
  let m = document.getElementById('hdiff-modal');
  if(!m){
    m = document.createElement('div');
    m.id = 'hdiff-modal';
    m.className = 'overlay';
    const inner = document.createElement('div');
    inner.className = 'modal lg';
    inner.style.maxWidth = '560px';
    const closeBtn = document.createElement('button');
    closeBtn.className = 'mc';
    closeBtn.onclick = function(){ cm('hdiff-modal'); };
    closeBtn.textContent = '✕';
    const title = document.createElement('div');
    title.className = 'mt';
    title.textContent = '⚠️ Hostname Farkı Tespit Edildi';
    const bodyEl = document.createElement('div');
    bodyEl.id = 'hdiff-body';
    inner.appendChild(closeBtn);
    inner.appendChild(title);
    inner.appendChild(bodyEl);
    m.appendChild(inner);
    document.body.appendChild(m);
  }
  document.getElementById('hdiff-body').innerHTML = body;
  om('hdiff-modal');
}

async function _applyHostnameDiffs(){
  const checks = document.querySelectorAll('#hdiff-body input[type=checkbox]');
  const selected = [];
  checks.forEach(cb=>{ if(cb.checked) selected.push(_pendingDiffs[parseInt(cb.dataset.i)]); });
  if(!selected.length){ toast('Hiçbir kayıt seçilmedi','err'); return; }
  try{
    const r = await api('POST','/api/inventory/rename-hostname', selected);
    toast(r.updated+' kayıt güncellendi','ok');
    cm('hdiff-modal');
    loadInventory();
  }catch(e){ toast(e.message,'err'); }
}

async function loadColOutputs(){
  const files=await api('GET','/api/collector/outputs');const el=document.getElementById('col-outputs');
  if(!files.length){el.innerHTML='<div class="empty"><div class="ei">📄</div><p>Henüz sonuç yok</p></div>';return;}
  el.innerHTML=`<div class="card" style="padding:0;overflow:hidden"><div class="tw"><table>
    <thead><tr><th>Dosya</th><th>Boyut</th><th>Tarih</th><th style="width:60px">Aç</th></tr></thead>
    <tbody>${files.map(f=>`<tr><td><code style="font-size:11px">${esc(f.name)}</code></td><td style="color:var(--text2)">${fmtSz(f.size)}</td><td style="color:var(--text2)">${esc(f.mtime)}</td><td><button class="btn btn-b btn-xs" onclick="viewColOut('${esc(f.name)}')">👁</button></td></tr>`).join('')}</tbody>
  </table></div></div>`;
}
async function viewColOut(fname){
  const d=await api('GET',`/api/collector/output/${enc(fname)}`);
  document.getElementById('mcr-t').textContent=fname;
  const ok=d.successful||[],fail=d.failed||[],skip=d.skipped||[];
  let html=`<div style="display:flex;gap:7px;margin-bottom:12px"><span class="tag tg">${ok.length} başarılı</span><span class="tag tr">${fail.length} başarısız</span><span class="tag tgr">${skip.length} atlandı</span></div>`;
  if(ok.length){
    html+=`<div class="ss" style="font-size:12px">✅ Başarılı</div>`;
    ok.forEach(r=>{
      const fields=Object.entries(r).filter(([k])=>!['device','ip'].includes(k)&&r[k]);
      html+=`<div class="card" style="margin-bottom:8px;padding:10px 14px">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px"><b>${esc(r.device)}</b><code style="color:var(--accent2);font-size:11px">${esc(r.ip)}</code></div>
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:4px;font-size:11px">
          ${fields.map(([k,v])=>`<div><span style="color:var(--text2)">${esc(k)}: </span><span>${esc(String(v))}</span></div>`).join('')}
        </div></div>`;
    });
  }
  if(fail.length){
    html+=`<div class="ss" style="font-size:12px">❌ Başarısız</div>`;
    fail.forEach(r=>{html+=`<div style="padding:7px 10px;background:rgba(239,68,68,.07);border-radius:var(--r);margin-bottom:4px"><b>${esc(r.device)}</b><div style="color:var(--danger);font-size:11px;margin-top:2px">${esc(r.error)}</div></div>`;});
  }
  document.getElementById('mcr-body').innerHTML=html;
  om('mcr');
}

// ════════════════════════════════════════════════════
// SCHEDULE
// ════════════════════════════════════════════════════
const DAYS=['sunday','monday','tuesday','wednesday','thursday','friday','saturday'];
const DAYTR=['Pazar','Pazartesi','Salı','Çarşamba','Perşembe','Cuma','Cumartesi'];

async function loadSchedule(){
  try{
    const r=await api('GET','/api/schedule');
    _schD=r.devices||{};
    // Enrich with device_type from inventory
    if(_iD.length){
      Object.entries(_schD).forEach(([ip,cfg])=>{
        const dev=_iD.find(d=>d.ip===ip);
        if(dev&&!cfg.device_type)cfg.device_type=dev.device_type||'';
      });
    }
    renderSchedule();
  }catch(e){toast('Schedule yüklenemedi','err');}
}
function renderSchedule(){
  const q=document.getElementById('sch-srch').value.toLowerCase();
  const tb=document.getElementById('sch-list');
  const entries=Object.entries(_schD).filter(([ip,cfg])=>
    ip.includes(q)||(cfg.name||'').toLowerCase().includes(q)||(cfg.device_type||'').toLowerCase().includes(q)
  );
  if(!entries.length){
    tb.innerHTML=`<tr><td colspan="8"><div class="empty"><div class="ei">⏰</div><p>Cihaz yok</p></div></td></tr>`;
    return;
  }
  tb.innerHTML=entries.map(([ip,cfg])=>{
    const id=ipToId(ip);
    const dt=cfg.device_type||'';
    const tc=dt.includes('cisco')?'tb':dt.includes('huawei')?'tg':dt.includes('forti')?'to':dt.includes('bigip')||dt.includes('f5')||dt.includes('velos')?'tr':'tgr';
    const dayOpts=DAYS.map((d,i)=>`<option value="${d}" ${cfg.day===d?'selected':''}>${DAYTR[i]}</option>`).join('');
    const hourOpts=Array.from({length:24},(_,i)=>`<option value="${i}" ${cfg.hour===i?'selected':''}>${String(i).padStart(2,'0')}</option>`).join('');
    const minOpts=Array.from({length:12},(_,i)=>i*5).map(m2=>`<option value="${m2}" ${(cfg.minute||0)===m2?'selected':''}>${String(m2).padStart(2,'0')}</option>`).join('');
    const invIdx=_iD.findIndex(d=>d.ip===ip);
    return `<tr>
      <td style="cursor:pointer" onclick="${invIdx>=0?`viewInv(${invIdx})`:''}">
        <b style="color:var(--accent)">${esc(cfg.name||ip)}</b>
        ${invIdx<0?'<span class="tag tr" style="margin-left:4px;font-size:9px">envanterde yok</span>':''}
      </td>
      <td><code style="color:var(--accent2);font-size:11px">${esc(ip)}</code></td>
      <td><span class="tag ${tc}">${esc(dt||'—')}</span></td>
      <td><select class="sch-sel" id="sch-day-${id}">${dayOpts}</select></td>
      <td><select class="sch-sel" id="sch-hr-${id}" style="width:58px">${hourOpts}</select></td>
      <td><select class="sch-sel" id="sch-min-${id}" style="width:52px">${minOpts}</select></td>
      <td style="text-align:center">
        <input type="checkbox" id="sch-en-${id}" ${cfg.enabled!==false?'checked':''} style="accent-color:var(--accent);width:16px;height:16px">
      </td>
      <td><div class="ab">
        ${invIdx>=0?`<button class="btn btn-s btn-i btn-xs" onclick="viewInv(${invIdx})">👁</button>`:''}
        <button class="btn btn-p btn-xs" onclick="saveOneSchedule('${esc(ip)}')">💾</button>
      </div></td>
    </tr>`;
  }).join('');
}
function ipToId(ip){return ip.replace(/[.:]/g,'_');}
async function saveOneSchedule(ip){
  const id=ipToId(ip);
  const dayEl=document.getElementById('sch-day-'+id);
  const hrEl=document.getElementById('sch-hr-'+id);
  const minEl=document.getElementById('sch-min-'+id);
  const enEl=document.getElementById('sch-en-'+id);
  if(!dayEl){toast('Eleman bulunamadi: '+id,'err');return;}
  const day=dayEl.value;
  const hour=parseInt(hrEl?.value||0);
  const minute=parseInt(minEl?.value||0);
  const enabled=enEl?.checked??true;
  try{
    const r=await api('PUT',`/api/schedule/${enc(ip)}`,{day,hour,minute,enabled,mode:'full'});
    _schD[ip]={..._schD[ip],day,hour,minute,enabled};
    const dayNames={monday:'Pazartesi',tuesday:'Salı',wednesday:'Çarşamba',
      thursday:'Perşembe',friday:'Cuma',saturday:'Cumartesi',sunday:'Pazar'};
    const hhmm=String(hour).padStart(2,'0')+':'+String(minute).padStart(2,'0');
    if(r.backup_started){
      toast('Kaydedildi — backup şimdi başlatıldı 🚀','ok');
    } else {
      toast('Kaydedildi — '+hhmm+' '+dayNames[day],'ok');
    }
  }catch(e){toast(e.message,'err');}
}

// ════════════════════════════════════════════════════
// USERS
// ════════════════════════════════════════════════════
async function loadUsers(){
  const d=await api('GET','/api/users');
  const tb=document.getElementById('utb');
  const all=[{username:'admin',role:'admin',system:true},...Object.entries(d).map(([u,v])=>({username:u,role:v.role||'user',system:false}))];
  tb.innerHTML=all.map(u=>`<tr>
    <td><b>${esc(u.username)}</b>${u.system?` <span class="tag to" style="margin-left:5px">sistem</span>`:''}</td>
    <td><span class="tag ${u.role==='admin'?'to':'tb'}">${u.role}</span></td>
    <td><div class="ab">
      <button class="btn btn-s btn-xs" onclick="openChPw('${esc(u.username)}')">🔑 Şifre</button>
      ${!u.system?`<button class="btn btn-d btn-xs" onclick="delUser('${esc(u.username)}')">🗑</button>`:''}
    </div></td></tr>`).join('');
}
function openAddUser(){document.getElementById('au-n').value='';document.getElementById('au-p').value='';document.getElementById('au-r').value='user';om('mau');}
async function addUser(){const n=document.getElementById('au-n').value.trim(),p=document.getElementById('au-p').value,r=document.getElementById('au-r').value;if(!n||!p){toast('Ad ve şifre gerekli','err');return;}try{await api('POST','/api/users',{username:n,password:p,role:r});toast('Eklendi','ok');cm('mau');loadUsers();}catch(e){toast(e.message,'err');}}
async function delUser(u){if(!confirm(`"${u}" silinecek?`))return;try{await api('DELETE',`/api/users/${enc(u)}`);toast('Silindi','ok');loadUsers();}catch(e){toast(e.message,'err');}}
function openChPw(u){document.getElementById('cp-u').value=u;document.getElementById('cp-name').textContent=u;document.getElementById('cp-p').value='';om('mcp');}
async function changeUserPw(){const u=document.getElementById('cp-u').value,p=document.getElementById('cp-p').value;if(u==='admin'){toast('Admin şifresi vault key ile aynıdır, buradan değiştirilemez','err');return;}if(!p){toast('Şifre boş olamaz','err');return;}try{await api('PUT',`/api/users/${enc(u)}/password`,{new_password:p});toast('Şifre değiştirildi','ok');cm('mcp');}catch(e){toast(e.message,'err');}}


// Init — oturum kontrolü
(async()=>{try{const r=await fetch('/api/me');if(r.ok){const d=await r.json();_role=d.role;_username=d.username;initApp();}}catch{}})();
</script>
</body>
</html>"""

# Şablon atama
TEMPLATE = _INLINE_TEMPLATE

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=5000)
    p.add_argument("--debug", action="store_true")
    args = p.parse_args()
    print(f"\n  🐙 Octopus Web  →  http://localhost:{args.port}\n")
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)
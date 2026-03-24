"""
parsers/fortigate.py
─────────────────────
FortiGate REST API envanter parser'ı.

Kullanılan endpoint:
  GET /api/v2/monitor/system/status   → model, sürüm, serial, uptime, hostname
  GET /api/v2/cmdb/system/global      → hostname (yedek)

API yanıtı JSON formatındadır; parse_fortigate() doğrudan
response.json()["results"] veya response.json() alır.
"""

from __future__ import annotations


def parse_fortigate(status_data: dict, global_data: dict | None = None) -> dict:
    """
    status_data : /api/v2/monitor/system/status yanıtı (dict)
    global_data : /api/v2/cmdb/system/global yanıtı (dict) — opsiyonel
    """
    data: dict = {"brand": "Fortinet FortiGate"}

    results = status_data.get("results", status_data)

    # ── Model ──────────────────────────────────────────────
    # results["model_name"] veya results["platform_full_name"]
    data["model"] = (
        results.get("model_name")
        or results.get("platform_full_name")
        or results.get("model")
    )

    # ── Hostname ───────────────────────────────────────────
    data["hostname"] = results.get("hostname")
    if not data["hostname"] and global_data:
        gresults = global_data.get("results", global_data)
        data["hostname"] = gresults.get("hostname")

    # ── Serial number ──────────────────────────────────────
    data["serial_no"] = results.get("serial") or results.get("serial_number")

    # ── Software / FortiOS version ─────────────────────────
    # "v7.4.3,build2573,231016"  veya  "v7.4.3"
    version_raw: str = results.get("version", "") or results.get("firmware_version", "")
    if version_raw.startswith("v"):
        version_raw = version_raw[1:]
    data["software_version"] = version_raw.split(",")[0] if version_raw else None
    data["build"] = None
    if "," in (results.get("version", "") or ""):
        parts = results["version"].split(",")
        if len(parts) > 1:
            data["build"] = parts[1].replace("build", "").strip()

    # ── Uptime ─────────────────────────────────────────────
    # results["system_time"]["uptime_sec"] (saniye) veya doğrudan "uptime"
    uptime_sec = None
    sys_time = results.get("system_time", {})
    if isinstance(sys_time, dict):
        uptime_sec = sys_time.get("uptime_sec")
    if uptime_sec is None:
        uptime_sec = results.get("uptime")

    if uptime_sec is not None:
        try:
            sec = int(uptime_sec)
            d, rem = divmod(sec, 86400)
            h, rem = divmod(rem, 3600)
            m = rem // 60
            data["uptime"] = f"{d} days, {h} hours, {m} minutes"
        except (ValueError, TypeError):
            data["uptime"] = str(uptime_sec)
    else:
        data["uptime"] = None

    # ── VDOM bilgisi ───────────────────────────────────────
    data["vdom_enabled"] = bool(results.get("virtual_domain_count", 0) > 1
                                or results.get("vdom_mode"))

    # ── HA bilgisi ─────────────────────────────────────────
    ha = results.get("ha_info", {})
    if ha and isinstance(ha, dict):
        data["ha_mode"]   = ha.get("mode")
        data["ha_role"]   = ha.get("role")
        data["ha_serial"] = ha.get("serial")
    else:
        data["ha_mode"] = data["ha_role"] = data["ha_serial"] = None

    return data

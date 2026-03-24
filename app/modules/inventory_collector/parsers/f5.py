"""
parsers/f5.py
──────────────
F5 BIG-IP iControl REST envanter parser'ı.

Kullanılan endpoint'ler:
  GET /mgmt/tm/sys/version          → sürüm, build, edition
  GET /mgmt/tm/sys/hardware         → model, serial, platform
  GET /mgmt/shared/identified-devices/config/device-info → hostname, machineId

API yanıtları JSON; parse_f5() doğrudan ilgili dict'leri alır.
"""

from __future__ import annotations


def parse_f5(
    version_data: dict,
    hardware_data: dict | None = None,
    device_info_data: dict | None = None,
) -> dict:
    """
    version_data     : GET /mgmt/tm/sys/version  yanıtı
    hardware_data    : GET /mgmt/tm/sys/hardware  yanıtı (opsiyonel)
    device_info_data : GET /mgmt/shared/identified-devices/config/device-info yanıtı (opsiyonel)
    """
    data: dict = {"brand": "F5 BIG-IP"}

    # ── Sürüm bilgisi (/mgmt/tm/sys/version) ──────────────
    # {"kind":"tm:sys:version:versionstats","selfLink":"...","entries":{...}}
    entries = version_data.get("entries", {})
    # entries içi: "https://.../version/0": {"nestedStats": {"entries": {...}}}
    nested: dict = {}
    for val in entries.values():
        if isinstance(val, dict) and "nestedStats" in val:
            nested = val["nestedStats"].get("entries", {})
            break

    def _stat(key: str) -> str | None:
        v = nested.get(key, {})
        return v.get("description") if isinstance(v, dict) else None

    data["software_version"] = _stat("Version")
    data["build"]            = _stat("Build")
    data["edition"]          = _stat("Edition")
    data["product"]          = _stat("Product")

    # ── Donanım bilgisi (/mgmt/tm/sys/hardware) ───────────
    if hardware_data:
        hw_entries = hardware_data.get("entries", {})
        for val in hw_entries.values():
            if not isinstance(val, dict):
                continue
            hw_nested = val.get("nestedStats", {}).get("entries", {})

            def _hw(key: str) -> str | None:
                v = hw_nested.get(key, {})
                return v.get("description") if isinstance(v, dict) else None

            platform = _hw("platform")
            if platform:
                data["model"]     = platform
                data["serial_no"] = _hw("chassisSerialNum") or _hw("serialNumber")
                data["marketing_name"] = _hw("marketingName")
                break

    if "model" not in data:
        data["model"] = None
    if "serial_no" not in data:
        data["serial_no"] = None

    # ── Cihaz bilgisi (/mgmt/shared/identified-devices) ───
    if device_info_data:
        data["hostname"]   = device_info_data.get("hostname")
        data["machine_id"] = device_info_data.get("machineId")
        data["management_ip"] = device_info_data.get("address")
        # model/serial yedek kaynak
        if not data.get("model"):
            data["model"] = device_info_data.get("platform")
        if not data.get("serial_no"):
            data["serial_no"] = device_info_data.get("chassisSerialNumber")
    else:
        data.setdefault("hostname", None)

    # ── Uptime ─────────────────────────────────────────────
    # /mgmt/tm/sys/clock veya /mgmt/tm/sys/version içinde bulunmaz doğrudan;
    # hardware_data içinde "uptime" nestedStat olabilir
    if hardware_data:
        hw_entries = hardware_data.get("entries", {})
        for val in hw_entries.values():
            if isinstance(val, dict):
                hw_nested = val.get("nestedStats", {}).get("entries", {})
                uptime_val = hw_nested.get("uptime", {})
                if isinstance(uptime_val, dict) and "description" in uptime_val:
                    data["uptime"] = uptime_val["description"]
                    break
    data.setdefault("uptime", None)

    return data

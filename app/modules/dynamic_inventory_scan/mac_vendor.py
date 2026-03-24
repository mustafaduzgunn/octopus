"""
app/modules/network_scanner/mac_vendor.py
──────────────────────────────────────────
MAC adresi → üretici adı.
Sadece macvendors.com REST API kullanır.
"""

from __future__ import annotations

import re
import requests

_API_URL = "https://api.macvendors.com/{mac}"
_TIMEOUT = 4.0


def _normalize(mac: str) -> str:
    return re.sub(r"[:\-\.\s]", "", mac).upper()


def lookup(mac: str, timeout: float = _TIMEOUT) -> str:
    """
    macvendors.com üzerinden MAC adresinin üreticisini sorgular.
    Ulaşılamazsa veya bulunamazsa 'Bilinmiyor' döner.
    """
    if not mac or mac.upper() in ("N/A", "UNKNOWN", ""):
        return "Bilinmiyor"

    normalized = _normalize(mac)
    if len(normalized) < 6:
        return "Bilinmiyor"

    mac_fmt = ":".join(normalized[i:i+2] for i in range(0, 6, 2))

    try:
        resp = requests.get(
            _API_URL.format(mac=mac_fmt),
            timeout=timeout,
            headers={"Accept": "text/plain"},
        )
        if resp.status_code == 200 and resp.text.strip():
            return resp.text.strip()
    except Exception:
        pass

    return "Bilinmiyor"
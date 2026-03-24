"""
app/modules/network_map/service.py
────────────────────────────────────
Network Map — Topoloji Keşif Motoru

Adım adım bağlantı tablosu oluşturur:
  lokal_cihaz | lokal_port | uzak_cihaz | uzak_port |
  lokal_po    | lokal_po_members | lokal_vlan |
  uzak_po     | uzak_vlan | aktif_vlan

Desteklenen cihaz tipleri:
  SSH (Netmiko) : cisco_ios, cisco_nxos, huawei, dell_force10, hp_comware
  Mevcut veri   : device_details.json'daki portchannel/neighbor/vlan verileri
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import TYPE_CHECKING

import paramiko
from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

if TYPE_CHECKING:
    from app.modules.password_manager.service import VaultService

logger = logging.getLogger(__name__)

_BASE          = Path(__file__).parent.parent.parent
DATA_DIR       = _BASE / "data"
INV_PATH       = DATA_DIR / "inventory.json"
DEV_DETAILS    = DATA_DIR / "device_details.json"
MAP_OUTPUT     = DATA_DIR / "network_map.json"

SSH_TIMEOUT    = 15
SSH_MAX_RETRY  = 3
SSH_RETRY_WAIT = 5   # saniye


# ── Veri modeli ────────────────────────────────────────────

@dataclass
class Link:
    """Tek bir bağlantı kaydı."""
    local_device:      str = ""
    local_port:        str = ""
    remote_device:     str = ""
    remote_port:       str = ""
    local_po:          str = ""          # Port-channel / Eth-Trunk adı
    local_po_members:  list[str] = field(default_factory=list)
    local_vlans:       list[int] = field(default_factory=list)
    remote_po:         str = ""
    remote_vlans:      list[int] = field(default_factory=list)
    active_vlans:      list[int] = field(default_factory=list)
    protocol:          str = ""          # CDP / LLDP
    ssh_error:         str = ""          # Uzak cihaza SSH yapılamazsa neden

    def key(self) -> tuple:
        """Bağlantı kimliği — duplicate tespiti için."""
        # Port-channel varsa o, yoksa port bazlı anahtar
        a = (self.local_device,  self.local_po  or self.local_port)
        b = (self.remote_device, self.remote_po or self.remote_port)
        return tuple(sorted([a, b]))

    def to_dict(self) -> dict:
        d = asdict(self)
        d["_key"] = str(self.key())
        return d


# ── Yardımcı: port normalize ───────────────────────────────

def _normalize_port(port: str) -> str:
    """
    Port adını kısaltır: GigabitEthernet1/0/1 → Gi1/0/1
    Bu sayede CDP ve LLDP bildirimleri eşleştirilebilir.
    """
    port = port.strip()
    prefixes = [
        ("HundredGigE",        "Hu"),
        ("TwentyFiveGigE",     "Twe"),
        ("FortyGigabitEthernet","Fo"),
        ("TenGigabitEthernet", "Te"),
        ("GigabitEthernet",    "Gi"),
        ("FastEthernet",       "Fa"),
        ("Ethernet",           "Et"),
        ("100GE",              "100GE"),
        ("40GE",               "40GE"),
        ("10GE",               "10GE"),
        ("GE",                 "GE"),
    ]
    for long, short in prefixes:
        if port.startswith(long):
            return short + port[len(long):]
    return port


def _strip_po_member_state(member: str) -> str:
    """'Gi1/0/1(P)' → 'Gi1/0/1'"""
    return re.sub(r"\([A-Za-z]+\)$", "", member).strip()


def _parse_vlan_range(vlan_str: str) -> list[int]:
    """
    '10,20-25,30' → [10, 20, 21, 22, 23, 24, 25, 30]
    'all' → [] (bilinmiyor / trunk-all)
    """
    vlans: list[int] = []
    if not vlan_str or vlan_str.strip().lower() in ("", "all", "none", "-"):
        return vlans
    for part in re.split(r"[,\s]+", vlan_str.strip()):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                a, b = part.split("-", 1)
                vlans.extend(range(int(a), int(b) + 1))
            except ValueError:
                pass
        else:
            try:
                vlans.append(int(part))
            except ValueError:
                pass
    return sorted(set(vlans))


# ── SSH yardımcıları ───────────────────────────────────────

def _ssh_command(ip: str, device_type: str, cred: dict,
                 commands: list[str]) -> dict[str, str]:
    """
    Birden fazla komutu tek SSH oturumunda çalıştırır.
    Returns: {cmd: output} veya raises exception.
    """
    conn = ConnectHandler(
        device_type=device_type,
        host=ip,
        username=cred.get("username", ""),
        password=cred.get("password", ""),
        timeout=SSH_TIMEOUT,
    )
    results: dict[str, str] = {}
    for cmd in commands:
        try:
            results[cmd] = conn.send_command(cmd, read_timeout=30)
        except Exception as exc:
            results[cmd] = f"ERROR: {exc}"
    conn.disconnect()
    return results


def _ssh_with_retry(ip: str, device_type: str, cred: dict,
                    commands: list[str]) -> tuple[dict[str, str], str]:
    """
    SSH retry wrapper. Returns (results_dict, error_str).
    error_str boşsa başarılı demektir.
    """
    last_err = ""
    for attempt in range(1, SSH_MAX_RETRY + 1):
        try:
            results = _ssh_command(ip, device_type, cred, commands)
            return results, ""
        except (NetmikoAuthenticationException,) as exc:
            last_err = f"Auth hatası: {exc}"
            break  # auth hatasında retry yok
        except (NetmikoTimeoutException,) as exc:
            last_err = f"Timeout: {exc}"
        except Exception as exc:
            last_err = str(exc)
        if attempt < SSH_MAX_RETRY:
            logger.debug("SSH retry %d/%d — %s: %s", attempt, SSH_MAX_RETRY, ip, last_err)
            time.sleep(SSH_RETRY_WAIT)
    return {}, last_err


# ── Port-channel tespiti ───────────────────────────────────

class PortChannelParser:
    """
    Cihaz tipine göre port-channel üyeliğini tespit eder.
    Önce device_details.json'a bakar (mevcut veri), gerekirse SSH çeker.
    """

    @staticmethod
    def find_po_for_port(port: str, portchannels: dict) -> tuple[str, list[str]]:
        """
        Verilen fiziksel port hangi port-channel'a üye?
        Returns: (po_name, [clean_members]) veya ("", [])
        """
        norm = _normalize_port(port)
        for po_name, po_info in portchannels.items():
            members = [_strip_po_member_state(m) for m in po_info.get("members", [])]
            members_norm = [_normalize_port(m) for m in members]
            if norm in members_norm or port in members:
                # Deduplicate members (bazı parserlarda çift gelir)
                seen = set()
                clean = []
                for m in members:
                    mn = _normalize_port(m)
                    if mn not in seen:
                        seen.add(mn)
                        clean.append(m)
                return po_name, clean
        return "", []

    @staticmethod
    def get_vlans_for_po_or_port(port: str, po_name: str, portchannels: dict) -> list[int]:
        """Port-channel ya da fiziksel portun VLAN listesini döndürür."""
        # PO varsa PO vlan'larına bak
        if po_name and po_name in portchannels:
            vlans = portchannels[po_name].get("vlans", [])
            if vlans:
                return sorted(set(vlans))
        # PO yoksa veya PO'da vlan boşsa — port adıyla portchannels'ta arama
        # (bazı parserlarda fiziksel portlar da portchannels altında tutuluyor)
        norm = _normalize_port(port)
        for name, info in portchannels.items():
            if _normalize_port(name) == norm:
                return sorted(set(info.get("vlans", [])))
        return []

    # ── Cisco SSH ile port detayı ──────────────────────────
    @staticmethod
    def cisco_get_port_detail(ip: str, cred: dict, port: str) -> dict:
        """
        Cisco IOS/NX-OS üzerinde port bilgisi çeker.
        Returns: {po_name, members, vlans}
        """
        norm = _normalize_port(port)
        cmds = [
            f"show interfaces {norm} trunk",
            f"show interfaces {norm} switchport",
            "show etherchannel summary",
        ]
        outputs, err = _ssh_with_retry(ip, "cisco_ios", cred, cmds)
        if err:
            return {"error": err}

        result: dict = {"po_name": "", "members": [], "vlans": []}

        # Port-channel üyeliğini bul
        ec_out = outputs.get("show etherchannel summary", "")
        for line in ec_out.splitlines():
            if norm.lower() in line.lower() or port.lower() in line.lower():
                # Örnek: Po1(SU)  LACP  Gi1/0/1(P) Gi1/0/2(P)
                m = re.search(r"(Po\d+)\s*\(", line)
                if m:
                    result["po_name"] = m.group(1)
                    # Po1 satırını bul
                    for l2 in ec_out.splitlines():
                        if l2.strip().startswith(result["po_name"]):
                            members = re.findall(r"([A-Za-z]{1,4}\d[\d/]*)\(", l2)
                            result["members"] = members
                            break

        # VLAN
        sw_out = outputs.get(f"show interfaces {norm} switchport", "")
        trunk_out = outputs.get(f"show interfaces {norm} trunk", "")

        vlans = []
        # Trunk allowed VLANs
        m = re.search(r"Trunking VLANs Allowed:\s*(.+)", trunk_out)
        if m:
            vlans = _parse_vlan_range(m.group(1))
        # Access VLAN
        if not vlans:
            m = re.search(r"Access Mode VLAN:\s*(\d+)", sw_out)
            if m:
                vlans = [int(m.group(1))]
        result["vlans"] = vlans
        return result

    @staticmethod
    def huawei_get_port_detail(ip: str, cred: dict, port: str) -> dict:
        """Huawei üzerinde port bilgisi çeker."""
        norm = _normalize_port(port)
        cmds = [
            f"display interface {norm}",
            f"display port vlan {norm}",
            "display eth-trunk",
        ]
        outputs, err = _ssh_with_retry(ip, "huawei", cred, cmds)
        if err:
            return {"error": err}

        result: dict = {"po_name": "", "members": [], "vlans": []}

        # Eth-Trunk üyeliği
        trunk_out = outputs.get("display eth-trunk", "")
        for line in trunk_out.splitlines():
            if norm.lower() in line.lower() or port.lower() in line.lower():
                m = re.search(r"(Eth-Trunk\d+)", line, re.IGNORECASE)
                if m:
                    result["po_name"] = m.group(1)
                    # Member listesi
                    members = re.findall(r"([A-Za-z0-9]+\d+/\d+/\d+)", trunk_out)
                    result["members"] = list(dict.fromkeys(members))
                    break

        # VLAN
        vlan_out = outputs.get(f"display port vlan {norm}", "")
        vlans = []
        m = re.search(r"(?:allowed vlan|trunk vlan)[^\n]*?(\d[\d\s,\-]+)", vlan_out, re.IGNORECASE)
        if m:
            vlans = _parse_vlan_range(m.group(1))
        if not vlans:
            m = re.search(r"(?:access vlan|untagged vlan)[^\n]*?(\d+)", vlan_out, re.IGNORECASE)
            if m:
                vlans = [int(m.group(1))]
        result["vlans"] = vlans
        return result

    @staticmethod
    def generic_get_port_detail(ip: str, device_type: str, cred: dict, port: str) -> dict:
        """Dell Force10, HP Comware vb. için genel port detayı."""
        norm = _normalize_port(port)
        cmds = [f"show interfaces {norm}", f"show running-config interface {norm}"]
        outputs, err = _ssh_with_retry(ip, device_type, cred, cmds)
        if err:
            return {"error": err}

        result: dict = {"po_name": "", "members": [], "vlans": []}
        combined = "\n".join(outputs.values())

        # channel-group veya port-channel eşleşmesi
        m = re.search(r"channel-group\s+(\d+)", combined, re.IGNORECASE)
        if m:
            result["po_name"] = f"Po{m.group(1)}"

        # VLAN
        m = re.search(r"(?:allowed vlan|trunk vlan)[^\n]*?(\d[\d\s,\-]+)", combined, re.IGNORECASE)
        if m:
            result["vlans"] = _parse_vlan_range(m.group(1))
        elif not result["vlans"]:
            m = re.search(r"(?:access vlan|switchport access)[^\n]*?(\d+)", combined, re.IGNORECASE)
            if m:
                result["vlans"] = [int(m.group(1))]
        return result


# ── Ana topoloji oluşturucu ────────────────────────────────

class TopologyBuilder:
    """
    Tüm inventory üzerinde adım adım bağlantı tablosunu oluşturur.
    """

    def __init__(self, vault: "VaultService", progress_cb=None):
        self.vault       = vault
        self.progress_cb = progress_cb  # (msg: str, pct: float) → None
        self.inv:         list[dict] = self._load_inv()
        self.dd:          dict       = self._load_dd()
        self.ip_map:      dict[str, dict] = {d["ip"]: d for d in self.inv}
        self.name_map:    dict[str, dict] = {d["name"].upper(): d for d in self.inv}

    def _load_inv(self) -> list[dict]:
        if not INV_PATH.exists():
            return []
        return json.loads(INV_PATH.read_text(encoding="utf-8"))

    def _load_dd(self) -> dict:
        if not DEV_DETAILS.exists():
            return {}
        return json.loads(DEV_DETAILS.read_text(encoding="utf-8"))

    def _log(self, msg: str, pct: float = -1) -> None:
        logger.info(msg)
        if self.progress_cb:
            self.progress_cb(msg, pct)

    def _get_cred(self, device: dict) -> dict:
        cred_id = device.get("credential_id", "")
        return self.vault.vault.get(cred_id, {})

    def _resolve_remote_device(self, remote_host: str) -> dict | None:
        """
        CDP/LLDP'den gelen remote_host ismini inventory cihazıyla eşleştirir.
        remote_host IP olabilir, kısa ad olabilir, FQDN olabilir.
        """
        if not remote_host:
            return None
        # Direkt IP eşleşmesi
        if remote_host in self.ip_map:
            return self.ip_map[remote_host]
        # Büyük harf isim eşleşmesi
        upper = remote_host.upper().split(".")[0]  # FQDN → kısa ad
        if upper in self.name_map:
            return self.name_map[upper]
        # Kısmi eşleşme
        for name_key, dev in self.name_map.items():
            if upper in name_key or name_key in upper:
                return dev
        return None

    def build(self) -> list[dict]:
        """
        Tüm inventory'yi tarar ve bağlantı tablosunu oluşturur.
        Returns: list of Link.to_dict()
        """
        links:       list[Link] = []
        seen_keys:   set        = set()   # duplicate önleme
        total = len(self.inv)

        for idx, local_dev in enumerate(self.inv):
            local_ip   = local_dev.get("ip", "")
            local_name = local_dev.get("name", local_ip)
            local_dt   = local_dev.get("device_type", "").lower()
            local_dd   = self.dd.get(local_ip, {})
            neighbors  = local_dd.get("neighbors", [])
            portchannels = local_dd.get("portchannels", {})

            if not neighbors:
                continue

            pct = (idx / total) * 100
            self._log(f"[{idx+1}/{total}] {local_name} — {len(neighbors)} komşu", pct)

            for nbr in neighbors:
                local_port  = nbr.get("local_port", "")
                remote_host = nbr.get("remote_host", "")
                remote_port = nbr.get("remote_port", "")
                protocol    = nbr.get("protocol", "")

                if not local_port or not remote_host:
                    continue

                # ── Adım 1: Temel bağlantı ────────────────
                link = Link(
                    local_device  = local_name,
                    remote_device = remote_host,
                    local_port    = local_port,
                    remote_port   = remote_port,
                    protocol      = protocol,
                )

                # ── Adım 8: Duplicate kontrolü (ön kontrol) ──
                # Uzak cihazın komşularında bu bağlantı zaten var mı?
                remote_dev = self._resolve_remote_device(remote_host)

                # ── Adım 2: Lokal port-channel ────────────
                # Önce neighbor kaydında hazır veri var mı?
                if nbr.get("portchannel"):
                    link.local_po         = nbr["portchannel"]
                    raw_members           = nbr.get("portchannel_members", [])
                    # Deduplicate
                    seen_m: set = set()
                    clean_m: list[str] = []
                    for m in raw_members:
                        mn = _normalize_port(_strip_po_member_state(m))
                        if mn not in seen_m:
                            seen_m.add(mn)
                            clean_m.append(m)
                    link.local_po_members = clean_m
                else:
                    po_name, po_members = PortChannelParser.find_po_for_port(
                        local_port, portchannels
                    )
                    link.local_po         = po_name
                    link.local_po_members = po_members

                # ── Adım 8: Duplicate — PO seviyesinde ───
                # Eğer bu PO'nun bir member'ı zaten işlendiyse atla
                dup_key = link.key()
                if dup_key in seen_keys:
                    logger.debug("Duplicate atlandı: %s", dup_key)
                    continue

                # ── Adım 3: Lokal VLAN ────────────────────
                if nbr.get("vlans"):
                    link.local_vlans = sorted(set(nbr["vlans"]))
                else:
                    link.local_vlans = PortChannelParser.get_vlans_for_po_or_port(
                        local_port, link.local_po, portchannels
                    )

                # ── Adım 5+6: Uzak cihaz SSH ─────────────
                if remote_dev:
                    remote_ip  = remote_dev.get("ip", "")
                    remote_dt  = remote_dev.get("device_type", "").lower()
                    remote_cred = self._get_cred(remote_dev)
                    remote_dd   = self.dd.get(remote_ip, {})
                    remote_pcs  = remote_dd.get("portchannels", {})

                    # Uzak portun PO'su — önce mevcut veriden
                    r_po, r_members = PortChannelParser.find_po_for_port(
                        remote_port, remote_pcs
                    )
                    link.remote_po = r_po

                    if not r_po or not PortChannelParser.get_vlans_for_po_or_port(
                        remote_port, r_po, remote_pcs
                    ):
                        # Mevcut veri yetersiz → SSH ile çek
                        if remote_ip and remote_cred:
                            self._log(f"  SSH → {remote_dev['name']} ({remote_ip})")
                            detail, err = self._fetch_remote_port_detail(
                                remote_ip, remote_dt, remote_cred, remote_port
                            )
                            if err:
                                link.ssh_error = err
                            else:
                                if detail.get("po_name") and not link.remote_po:
                                    link.remote_po = detail["po_name"]
                                if detail.get("vlans"):
                                    link.remote_vlans = detail["vlans"]
                        else:
                            link.ssh_error = "Credential yok veya IP çözümlenemedi"

                    # Uzak VLAN mevcut veriden
                    if not link.remote_vlans:
                        link.remote_vlans = PortChannelParser.get_vlans_for_po_or_port(
                            remote_port, link.remote_po, remote_pcs
                        )
                else:
                    link.ssh_error = "Uzak cihaz inventory'de bulunamadı"

                # ── Adım 7: Aktif VLAN (kesişim) ─────────
                if link.local_vlans and link.remote_vlans:
                    link.active_vlans = sorted(
                        set(link.local_vlans) & set(link.remote_vlans)
                    )
                elif link.local_vlans:
                    link.active_vlans = link.local_vlans
                elif link.remote_vlans:
                    link.active_vlans = link.remote_vlans

                seen_keys.add(dup_key)
                links.append(link)

        # ── Adım 9: Son duplicate temizliği ───────────────
        final_links = self._deduplicate(links)
        self._log(f"Topoloji tamamlandı: {len(final_links)} bağlantı", 100)
        return [l.to_dict() for l in final_links]

    def _fetch_remote_port_detail(
        self, ip: str, device_type: str, cred: dict, port: str
    ) -> tuple[dict, str]:
        """Uzak cihazdan port detayını cihaz tipine göre çeker."""
        try:
            if "cisco" in device_type:
                detail = PortChannelParser.cisco_get_port_detail(ip, cred, port)
            elif "huawei" in device_type:
                detail = PortChannelParser.huawei_get_port_detail(ip, cred, port)
            else:
                detail = PortChannelParser.generic_get_port_detail(ip, device_type, cred, port)

            if "error" in detail:
                return {}, detail["error"]
            return detail, ""
        except Exception as exc:
            return {}, str(exc)

    @staticmethod
    def _deduplicate(links: list[Link]) -> list[Link]:
        """
        Port-channel bağlantılarını tekrar kontrol eder:
        Aynı PO'ya ait birden fazla member satırı varsa tek satıra indirir.
        """
        final:    list[Link] = []
        seen_keys: set       = set()

        for link in links:
            k = link.key()
            if k not in seen_keys:
                seen_keys.add(k)
                final.append(link)
            else:
                # Zaten var — mevcut kaydı güncelle (VLAN gibi eksik veri varsa tamamla)
                for existing in final:
                    if existing.key() == k:
                        if not existing.local_vlans and link.local_vlans:
                            existing.local_vlans = link.local_vlans
                        if not existing.remote_vlans and link.remote_vlans:
                            existing.remote_vlans = link.remote_vlans
                        if not existing.active_vlans and link.active_vlans:
                            existing.active_vlans = link.active_vlans
                        break
        return final


# ── Draw.io XML üreticisi ──────────────────────────────────

def generate_drawio(links: list[dict]) -> str:
    """
    Bağlantı listesinden Draw.io XML oluşturur.
    Cihazlar otomatik konumlandırılır (kaba ızgara düzeni).
    """
    import html as _html

    # Benzersiz cihazları topla
    devices: dict[str, int] = {}  # name → cell_id
    cell_id = 2  # 0 ve 1 draw.io tarafından ayrılmış

    for link in links:
        for name in (link["local_device"], link["remote_device"]):
            if name and name not in devices:
                devices[name] = cell_id
                cell_id += 1

    # Konumlandırma — basit ızgara
    COLS   = 5
    COL_W  = 200
    ROW_H  = 120
    NODE_W = 160
    NODE_H = 60

    node_positions: dict[str, tuple[int, int]] = {}
    for i, name in enumerate(devices):
        col = i % COLS
        row = i // COLS
        node_positions[name] = (col * COL_W + 20, row * ROW_H + 20)

    # XML başlangıcı
    cells: list[str] = []

    # Cihaz kutucukları
    for name, cid in devices.items():
        x, y   = node_positions[name]
        label  = _html.escape(name)
        cells.append(
            f'    <mxCell id="{cid}" value="{label}" style="rounded=1;whiteSpace=wrap;'
            f'html=1;fillColor=#dae8fc;strokeColor=#6c8ebf;fontStyle=1;fontSize=11;" '
            f'vertex="1" parent="1">\n'
            f'      <mxGeometry x="{x}" y="{y}" width="{NODE_W}" height="{NODE_H}" as="geometry"/>\n'
            f'    </mxCell>'
        )

    # Bağlantı okları
    for i, link in enumerate(links):
        src_id = devices.get(link["local_device"])
        tgt_id = devices.get(link["remote_device"])
        if not src_id or not tgt_id:
            continue

        eid = cell_id + i

        # Kenar etiketi: lokal port / uzak port (varsa PO adı)
        lo_lbl  = link["local_po"]  or _normalize_port(link["local_port"])
        re_lbl  = link["remote_po"] or _normalize_port(link["remote_port"])
        vlans   = link.get("active_vlans", [])
        vl_str  = ""
        if vlans:
            if len(vlans) <= 6:
                vl_str = f"VL:{','.join(map(str,vlans))}"
            else:
                vl_str = f"VL:{vlans[0]}..{vlans[-1]}({len(vlans)})"

        mid_lbl = _html.escape(vl_str)
        src_lbl = _html.escape(lo_lbl)
        tgt_lbl = _html.escape(re_lbl)

        # Link kalınlığı: PO bağlantısı daha kalın
        thickness = "4" if link.get("local_po") else "2"
        color     = "#23A26D" if link.get("active_vlans") else "#555555"

        cells.append(
            f'    <mxCell id="{eid}" value="{mid_lbl}" '
            f'style="edgeStyle=orthogonalEdgeStyle;html=1;exitX=0.5;exitY=1;exitDx=0;exitDy=0;'
            f'entryX=0.5;entryY=0;entryDx=0;entryDy=0;strokeWidth={thickness};strokeColor={color};" '
            f'edge="1" source="{src_id}" target="{tgt_id}" parent="1">\n'
            f'      <mxGeometry relative="1" as="geometry"/>\n'
            f'    </mxCell>\n'
            f'    <mxCell id="{eid}sl" value="{src_lbl}" style="resizable=0;html=1;align=left;'
            f'verticalAlign=bottom;labelBackgroundColor=none;fontSize=9;" '
            f'vertex="1" connectable="0" parent="{eid}">\n'
            f'      <mxGeometry x="-0.8" relative="1" as="geometry"><mxPoint as="offset"/></mxGeometry>\n'
            f'    </mxCell>\n'
            f'    <mxCell id="{eid}tl" value="{tgt_lbl}" style="resizable=0;html=1;align=right;'
            f'verticalAlign=top;labelBackgroundColor=none;fontSize=9;" '
            f'vertex="1" connectable="0" parent="{eid}">\n'
            f'      <mxGeometry x="0.8" relative="1" as="geometry"><mxPoint as="offset"/></mxGeometry>\n'
            f'    </mxCell>'
        )

    cells_xml = "\n".join(cells)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<mxfile host="Octopus NMS">\n'
        '  <diagram name="Network Map">\n'
        '    <mxGraphModel>\n'
        '      <root>\n'
        '        <mxCell id="0"/>\n'
        '        <mxCell id="1" parent="0"/>\n'
        f'{cells_xml}\n'
        '      </root>\n'
        '    </mxGraphModel>\n'
        '  </diagram>\n'
        '</mxfile>\n'
    )


# ── Sonuç kaydet / yükle ───────────────────────────────────

def save_map(links: list[dict]) -> None:
    MAP_OUTPUT.write_text(
        json.dumps(links, indent=2, ensure_ascii=False), encoding="utf-8"
    )


def load_map() -> list[dict]:
    if not MAP_OUTPUT.exists():
        return []
    try:
        return json.loads(MAP_OUTPUT.read_text(encoding="utf-8"))
    except Exception:
        return []

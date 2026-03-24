"""
app/modules/kamu_yeni_vlan/module.py
─────────────────────────────────────
Çalışma modları:
  - main.py üzerinden : selected.run(vault)
  - Doğrudan          : python -m app.modules.kamu_yeni_vlan.module
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from netmiko import ConnectHandler

from app.core.base_module import BaseModule
from app.common.vault_helper import resolve_vault

if TYPE_CHECKING:
    from app.modules.password_manager.service import VaultService

logger = logging.getLogger(__name__)

_BASE = Path(__file__).parent.parent.parent
DATA_DIR = _BASE / "data"
BACKUP_DIR = _BASE / "backups" / "kamu_yeni_vlan"
PORTS_PATH = Path(__file__).parent / "ports.json"
INVENTORY_PATH = DATA_DIR / "inventory.json"
CUSTOM_TAG = "customer_new_vlan"


def _load_inventory() -> list[dict]:
    with open(INVENTORY_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def _filter_by_tag(inventory: list[dict], tag: str) -> list[dict]:
    return [d for d in inventory if tag in d.get("tags", [])]


def _load_ports() -> dict:
    if not PORTS_PATH.exists():
        return {}
    with open(PORTS_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def _parse_cisco_vlans(output: str) -> set[int]:
    used: set[int] = set()
    for line in output.splitlines():
        parts = line.split()
        if parts and parts[0].isdigit():
            used.add(int(parts[0]))
    return used


def _find_free_vlans(used: set[int], start: int = 1100, end: int = 2001) -> set[int]:
    return {v for v in range(start, end) if v not in used}


def _collect_common_free_vlans(
    devices: list[dict], vault: VaultService
) -> list[int] | None:
    common_free: set[int] | None = None

    for device in devices:
        print(f"  Kontrol ediliyor: {device['name']} ({device['ip']})")
        cred_id = device.get("credential_id", "")

        if cred_id not in vault.vault:
            print(f"  [HATA] Credential bulunamadı: {cred_id}")
            logger.error("Credential bulunamadı: %s", cred_id)
            return None

        cred = vault.vault[cred_id]
        try:
            conn = ConnectHandler(
                device_type=device["device_type"],
                host=device["ip"],
                username=cred["username"],
                password=cred["password"],
            )
            output = conn.send_command("show vlan brief")
            conn.disconnect()

            used = _parse_cisco_vlans(output)
            free = _find_free_vlans(used)
            common_free = free if common_free is None else common_free & free

        except Exception as exc:
            logger.exception("VLAN tarama hatası — %s: %s", device["name"], exc)
            print(f"  [HATA] {device['name']}: {exc}")
            return None

    return sorted(common_free) if common_free else []


def _take_backup(conn: ConnectHandler, device: dict) -> bool:
    try:
        dt = device["device_type"].lower()
        if "cisco" in dt:
            output = conn.send_command("show running-config", read_timeout=120)
        elif "huawei" in dt:
            output = conn.send_command("display current-configuration", read_timeout=120)
        else:
            logger.warning("Backup desteklenmiyor: %s", device["device_type"])
            return False

        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = BACKUP_DIR / f"{device['name']}_{timestamp}.cfg"
        path.write_text(output, encoding="utf-8")

        print(f"  Backup alındı: {path.name}")
        logger.info("Backup alındı: %s", path)
        return True

    except Exception as exc:
        logger.exception("Backup hatası — %s: %s", device["name"], exc)
        print(f"  [HATA] Backup alınamadı ({device['name']}): {exc}")
        return False


def _push_vlan(
    devices: list[dict],
    vault: VaultService,
    vlan_id: str,
    vlan_name: str,
) -> None:
    ports_data = _load_ports()

    for device in devices:
        print(f"\n  Yapılandırılıyor: {device['name']}")
        cred = vault.vault[device["credential_id"]]

        try:
            conn = ConnectHandler(
                device_type=device["device_type"],
                host=device["ip"],
                username=cred["username"],
                password=cred["password"],
            )

            if not _take_backup(conn, device):
                print("  Backup alınamadı, cihaz atlanıyor.")
                conn.disconnect()
                continue

            dev_data = ports_data.get(device["name"], {})
            trunk_ports: list[str] = dev_data.get("trunk_ports", [])
            dt = device["device_type"].lower()

            if "cisco" in dt:
                cmds = [f"vlan {vlan_id}", f"name {vlan_name}"]
                for port in trunk_ports:
                    cmds += [
                        f"interface {port}",
                        "switchport mode trunk",
                        f"switchport trunk allowed vlan add {vlan_id}",
                        "exit",
                    ]
                conn.send_config_set(cmds)
                conn.save_config()

            elif "huawei" in dt:
                conn.send_command_timing("system-view")
                conn.send_command_timing(f"vlan {vlan_id}")
                conn.send_command_timing(f"name {vlan_name}")
                conn.send_command_timing("quit")
                conn.send_command_timing("commit")

                for port in trunk_ports:
                    print(f"    Port: {port}")
                    out = conn.send_command_timing(f"interface {port}")
                    if "Error" in out:
                        print(f"    [HATA] Port atlandı: {port}")
                        continue
                    conn.send_command_timing("port link-type trunk")
                    conn.send_command_timing(f"port trunk allow-pass vlan {vlan_id}")
                    conn.send_command_timing("quit")

                conn.send_command_timing("commit")
                conn.send_command_timing("return")
                save_out = conn.send_command_timing("save")
                if "Y/N" in save_out or "[Y/N]" in save_out:
                    conn.send_command_timing("Y")

            conn.disconnect()
            print(f"  VLAN {vlan_id} başarıyla uygulandı.")
            logger.info("VLAN %s uygulandı — %s", vlan_id, device["name"])

        except Exception as exc:
            logger.exception("Config gönderilemedi — %s: %s", device["name"], exc)
            print(f"  [HATA] {device['name']}: {exc}")


class KamuYeniVlanModule(BaseModule):
    """Kamu VLAN oluşturma ve trunk yapılandırma modülü."""

    def info(self) -> dict[str, str]:
        return {
            "name": "Kamu Yeni VLAN",
            "description": "Ortak boş VLAN bulur ve tüm cihazlara uygular.",
        }

    def run(self, vault: VaultService | None = None) -> None:
        v = resolve_vault(vault)

        inventory = _load_inventory()
        devices = _filter_by_tag(inventory, CUSTOM_TAG)

        if not devices:
            print(f"  '{CUSTOM_TAG}' tag'ine sahip cihaz bulunamadı.")
            input("  Enter'a basın...")
            return

        print(f"\n  {len(devices)} cihaz taranıyor...\n")
        common_free = _collect_common_free_vlans(devices, v)

        if not common_free:
            print("  Ortak boş VLAN bulunamadı.")
            input("  Enter'a basın...")
            return

        print("\n  Ortak boş VLAN'lar (ilk 20):")
        print(" ", common_free[:20])

        vlan_id = input("\n  Kullanılacak VLAN ID: ").strip()
        if not vlan_id.isdigit() or int(vlan_id) not in common_free:
            print("  Geçersiz VLAN ID.")
            input("  Enter'a basın...")
            return

        vlan_name = input("  VLAN adı: ").strip()
        if not vlan_name:
            print("  VLAN adı boş olamaz.")
            input("  Enter'a basın...")
            return

        print(f"\n  VLAN {vlan_id} ({vlan_name}) tüm cihazlara uygulanacak.")
        if input("  Onaylıyor musunuz? (y/n): ").strip().lower() != "y":
            print("  İptal edildi.")
            return

        _push_vlan(devices, v, vlan_id, vlan_name)
        print("\n  İşlem tamamlandı.")
        input("  Enter'a basın...")


if __name__ == "__main__":
    KamuYeniVlanModule().run()

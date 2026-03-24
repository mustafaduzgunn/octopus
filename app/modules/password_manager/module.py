"""
app/modules/password_manager/module.py
"""

from __future__ import annotations

import logging
import threading
from getpass import getpass
from pathlib import Path
from typing import TYPE_CHECKING

import pyperclip

from app.core.base_module import BaseModule
from app.common.utils import clear_screen
from app.common.vault_helper import resolve_vault
from .service import VaultService
from .settings import PasswordSettings

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

_SETTINGS_PATH = str(Path(__file__).parent.parent.parent / "data" / "settings.json")

# Alan adında bu kelimeler geçiyorsa "gizli" sayılır
_SECRET_KEYWORDS = ("token", "password", "secret", "key", "pass")


def _is_secret(field_name: str) -> bool:
    return any(kw in field_name.lower() for kw in _SECRET_KEYWORDS)


def _clear_clipboard() -> None:
    pyperclip.copy("")
    print("  Pano temizlendi.")


def _mask(value: str) -> str:
    """Gizli alanı tamamen maskeler."""
    return "***"


def _input_fields(existing: dict | None = None) -> dict[str, str]:
    """
    Varsayılan username + password sorar (boş bırakılabilir),
    ardından ek alan girişine izin verir.
    existing verilirse düzenleme modunda çalışır.
    Değer olarak '-' girilirse alan silinir.
    """
    entry: dict[str, str] = dict(existing) if existing else {}

    if existing:
        # ── Düzenleme modu ───────────────────────────────────────────
        print("\n  Mevcut alanlar:")
        for k, v in existing.items():
            print(f"    {k} = {'***' if _is_secret(k) else v}")
        print()
        print("  Güncellemek için aynı alan adını girin.")
        print("  Silmek için değer olarak  -  girin.")
        print("  Bitirmek için alan adını boş bırakın.\n")
    else:
        # ── Yeni kayıt modu — önce varsayılan alanları sor ──────────
        print("\n  Varsayılan alanlar (boş bırakılabilir):\n")

        username = input("  username: ").strip()
        if username:
            entry["username"] = username

        password = getpass("  password (gizli): ")
        if password:
            entry["password"] = password

        print("\n  Ek alan eklemek istiyorsanız girin (boş alan adıyla bitirin).")
        print("  Örnek: api_token, url, note, vdom\n")

    while True:
        field = input("  Alan adı: ").strip()
        if not field:
            break

        if _is_secret(field):
            value = getpass(f"  {field} (gizli): ")
        else:
            value = input(f"  {field}: ").strip()

        if value == "-":
            if field in entry:
                del entry[field]
                print(f"  '{field}' silindi.")
            else:
                print(f"  '{field}' zaten yok.")
        else:
            entry[field] = value

    return entry


class PasswordManagerModule(BaseModule):
    """Şifreli kasa yönetimi modülü."""

    def info(self) -> dict[str, str]:
        return {
            "name": "Password Manager",
            "description": "Şifreli kasa yönetimi.",
        }

    def run(self, vault: VaultService | None = None) -> None:
        clear_screen()
        v = resolve_vault(vault)
        settings = PasswordSettings(_SETTINGS_PATH)
        session_pin = getpass("  Oturum PIN'i belirleyin: ")

        menu = {
            "1": ("Kayıt Ekle",            lambda: self._add(v)),
            "2": ("Kayıt Düzenle",         lambda: self._edit(v, session_pin)),
            "3": ("Kayıtları Listele",     lambda: self._list(v)),
            "4": ("Şifre Kopyala",         lambda: self._copy_password(v, session_pin)),
            "5": ("Alan Kopyala",          lambda: self._copy_field(v, session_pin)),
            "6": ("Kayıt Sil",             lambda: self._delete(v)),
            "7": ("Şifre Üret",            lambda: self._generate(settings)),
        }

        while True:
            print()
            for k, (lbl, _) in menu.items():
                print(f"  [{k}] {lbl}")
            print("  [0] Geri\n")

            choice = input("  Seçim: ").strip()

            if choice == "0":
                break
            if choice in menu:
                menu[choice][1]()
            else:
                print("  Geçersiz seçim.")

    # ── [1] Kayıt Ekle ───────────────────────────────────────

    def _add(self, vault: VaultService) -> None:
        service = input("\n  Servis / kayıt adı: ").strip()
        if not service:
            print("  Servis adı boş olamaz.")
            return
        if service in vault.vault:
            print(f"  '{service}' zaten mevcut. Düzenlemek için [2] kullanın.")
            return

        entry = _input_fields()
        if not entry:
            print("  En az bir alan girilmeli.")
            return

        vault.add(service, entry)
        print(f"\n  '{service}' kaydedildi. ({len(entry)} alan)")
        logger.info("Kayıt eklendi: %s (%d alan)", service, len(entry))

    # ── [2] Kayıt Düzenle ────────────────────────────────────

    def _edit(self, vault: VaultService, session_pin: str) -> None:
        if not vault.vault:
            print("  Kasa boş.")
            return

        service = input("\n  Düzenlenecek servis adı: ").strip()
        if service not in vault.vault:
            print(f"  '{service}' bulunamadı.")
            return

        pin = getpass("  PIN: ")
        if pin != session_pin:
            print("  Yanlış PIN.")
            logger.warning("Yanlış PIN — düzenleme: %s", service)
            return

        updated = _input_fields(existing=vault.vault[service])
        if not updated:
            confirm = input("  Tüm alanlar silindi. Yine de kaydet? (e/h): ").strip().lower()
            if confirm != "e":
                print("  İptal edildi.")
                return

        vault.add(service, updated)
        print(f"\n  '{service}' güncellendi. ({len(updated)} alan)")
        logger.info("Kayıt güncellendi: %s", service)

    # ── [3] Kayıtları Listele ────────────────────────────────

    def _list(self, vault: VaultService) -> None:
        if not vault.vault:
            print("\n  Kasa boş.")
            return

        print(f"\n  {'─'*48}")
        for svc, data in vault.vault.items():
            print(f"  📁 {svc}")
            for field, value in data.items():
                # Gizli alanlar tamamen maskelenir
                display = "***" if _is_secret(field) else value
                print(f"       {field:<18}: {display}")
            print(f"  {'─'*48}")
        print(f"  Toplam {len(vault.vault)} kayıt.")

    # ── [4] Şifre Kopyala ────────────────────────────────────
    # Kayıttaki 'password' alanını doğrudan kopyalar.
    # Birden fazla gizli alan varsa hangisini istediğini sorar.

    def _copy_password(self, vault: VaultService, session_pin: str) -> None:
        if not vault.vault:
            print("  Kasa boş.")
            return

        service = input("\n  Servis adı: ").strip()
        if service not in vault.vault:
            print(f"  '{service}' bulunamadı.")
            return

        record = vault.vault[service]

        # 'password' alanı doğrudan var mı?
        if "password" in record:
            target_field = "password"
        else:
            # Gizli alanları bul
            secret_fields = [f for f in record if _is_secret(f)]
            if not secret_fields:
                print("  Bu kayıtta gizli alan bulunamadı.")
                return
            if len(secret_fields) == 1:
                target_field = secret_fields[0]
            else:
                print(f"\n  Birden fazla gizli alan var:")
                for i, f in enumerate(secret_fields, 1):
                    print(f"    {i}. {f}")
                raw = input("  Kopyalanacak alan numarası: ").strip()
                if not raw.isdigit() or not (1 <= int(raw) <= len(secret_fields)):
                    print("  Geçersiz seçim.")
                    return
                target_field = secret_fields[int(raw) - 1]

        pin = getpass("  PIN: ")
        if pin != session_pin:
            print("  Yanlış PIN.")
            logger.warning("Yanlış PIN — kopyalama: %s", service)
            return

        pyperclip.copy(record[target_field])
        print(f"  '{target_field}' kopyalandı (10 sn sonra temizlenecek).")
        threading.Timer(10.0, _clear_clipboard).start()

    # ── [5] Alan Kopyala ─────────────────────────────────────
    # Herhangi bir alanı (URL, username, vb.) kopyalar.

    def _copy_field(self, vault: VaultService, session_pin: str) -> None:
        if not vault.vault:
            print("  Kasa boş.")
            return

        service = input("\n  Servis adı: ").strip()
        if service not in vault.vault:
            print(f"  '{service}' bulunamadı.")
            return

        record = vault.vault[service]
        fields = list(record.keys())

        print(f"\n  '{service}' alanları:")
        for i, f in enumerate(fields, 1):
            marker = "🔒" if _is_secret(f) else "  "
            print(f"    {i}. {marker} {f}")

        raw = input("\n  Alan numarası: ").strip()
        if not raw.isdigit() or not (1 <= int(raw) <= len(fields)):
            print("  Geçersiz seçim.")
            return

        field = fields[int(raw) - 1]

        if _is_secret(field):
            pin = getpass("  PIN: ")
            if pin != session_pin:
                print("  Yanlış PIN.")
                logger.warning("Yanlış PIN — alan kopyalama: %s / %s", service, field)
                return
            timeout = 10
        else:
            timeout = 30

        pyperclip.copy(record[field])
        print(f"  '{field}' kopyalandı ({timeout} sn sonra temizlenecek).")
        threading.Timer(float(timeout), _clear_clipboard).start()

    # ── [6] Kayıt Sil ────────────────────────────────────────

    def _delete(self, vault: VaultService) -> None:
        if not vault.vault:
            print("  Kasa boş.")
            return

        service = input("\n  Silinecek servis adı: ").strip()
        if service not in vault.vault:
            print(f"  '{service}' bulunamadı.")
            return

        confirm = input(f"  '{service}' silinecek. Emin misiniz? (e/h): ").strip().lower()
        if confirm != "e":
            print("  İptal edildi.")
            return

        vault.delete(service)
        print(f"  '{service}' silindi.")
        logger.info("Kayıt silindi: %s", service)

    # ── [7] Şifre Üret ───────────────────────────────────────

    def _generate(self, settings: PasswordSettings) -> None:
        password = settings.generate()
        print(f"\n  Üretilen: {password}")
        pyperclip.copy(password)
        threading.Timer(30.0, _clear_clipboard).start()
        print("  Panoya kopyalandı (30 sn sonra temizlenecek).")


if __name__ == "__main__":
    PasswordManagerModule().run()

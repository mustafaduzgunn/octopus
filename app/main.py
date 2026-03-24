"""
app/main.py
───────────
Uygulama giriş noktası.

DÜZELTME (v3):
  - VaultService burada bir kez kimlik doğrulaması yapıyor.
  - Her modülün run(vault) çağrısına açık vault örneği iletiliyor.
  - Kullanıcı artık modüller arasında geçerken master password girmiyor.
"""

from __future__ import annotations

import logging
from getpass import getpass
from pathlib import Path

from app.core.logging_setup import configure_logging
from app.core.module_loader import load_modules
from app.common.banner import show_banner
from app.common.utils import clear_screen
from app.modules.password_manager.service import VaultService

logger = logging.getLogger(__name__)

_BASE = Path(__file__).parent
VAULT_PATH = _BASE / "data" / "vault.dat"


def _safe_choice(max_index: int) -> int | None:
    """Kullanıcıdan güvenli menü seçimi alır.

    Returns:
        Geçerli seçim (0 = çıkış), ya da None (geçersiz giriş).
    """
    raw = input("Seçiminiz: ").strip()
    if not raw.isdigit():
        print("  Geçersiz giriş. Lütfen bir sayı girin.")
        return None
    choice = int(raw)
    if choice < 0 or choice > max_index:
        print(f"  Geçersiz seçim. 0-{max_index} arasında bir değer girin.")
        return None
    return choice


def _open_vault() -> VaultService:
    """Vault'u açar; yanlış şifrede tekrar sorar.

    Returns:
        Kimliği doğrulanmış, açık VaultService örneği.
    """
    vault = VaultService(str(VAULT_PATH))
    while True:
        master = getpass("Master Password: ")
        if vault.authenticate(master):
            logger.info("Vault başarıyla açıldı.")
            return vault
        print("  Yanlış şifre. Tekrar deneyin.")


def main() -> None:
    configure_logging()
    logger.info("Octopus başlatılıyor.")

    modules = load_modules()
    if not modules:
        print("Hiç modül yüklenemedi. Çıkılıyor.")
        logger.error("Yüklenecek modül bulunamadı.")
        return

    # Vault tek seferde açılıyor — tüm modüller bu örneği paylaşıyor
    #clear_screen()
    show_banner()
    vault = _open_vault()

    while True:
        #clear_screen()
        show_banner()

        for i, m in enumerate(modules, 1):
            print(f"  {i} - {m.info()['name']}")
        print("  0 - Çıkış\n")

        choice = _safe_choice(len(modules))
        if choice is None:
            input("  Enter'a basın...")
            continue

        if choice == 0:
            logger.info("Kullanıcı çıkış yaptı.")
            break

        selected = modules[choice - 1]
        logger.info("Modül çalıştırılıyor: %s", selected.info()["name"])
        try:
            selected.run(vault)
        except Exception as exc:
            logger.exception("Modül çalışırken beklenmeyen hata: %s", exc)
            print(f"\n  [HATA] Modül çöktü: {exc}")
            input("  Enter'a basın...")


if __name__ == "__main__":
    main()

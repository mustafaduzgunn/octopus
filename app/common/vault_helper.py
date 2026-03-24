"""
app/common/vault_helper.py
──────────────────────────
Standalone modda vault açmak için ortak yardımcı.

Modüller bu fonksiyonu kullanarak kod tekrarından kaçınır:

    from app.common.vault_helper import resolve_vault

    def run(self, vault=None):
        vault = resolve_vault(vault)
        ...
"""

from __future__ import annotations

from getpass import getpass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.modules.password_manager.service import VaultService

_VAULT_PATH = Path(__file__).parent.parent / "data" / "vault.dat"


def resolve_vault(vault: VaultService | None) -> VaultService:
    """Vault zaten açıksa döndür; değilse şifre sorarak aç.

    Args:
        vault: main.py'den gelen vault örneği ya da None.

    Returns:
        Kimliği doğrulanmış, açık VaultService örneği.
    """
    if vault is not None:
        return vault

    # Standalone mod: bu modül doğrudan çalıştırılıyor
    from app.modules.password_manager.service import VaultService
    from app.core.logging_setup import configure_logging
    configure_logging()

    v = VaultService(str(_VAULT_PATH))
    while True:
        master = getpass("Master Password: ")
        if v.authenticate(master):
            return v
        print("  Yanlış şifre. Tekrar deneyin.")

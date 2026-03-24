"""
app/common/vault_utils.py
─────────────────────────
Standalone modda vault açmak için ortak yardımcı.

NOT: Bu dosya vault_helper.py ile aynı amaca hizmet ediyordu.
     Gereksiz tekrarı önlemek için vault_helper.resolve_vault() fonksiyonu
     tercih edilmeli; bu modül geriye dönük uyumluluk için korunuyor.

Kullanım:
    from app.common.vault_utils import require_vault
    vault = require_vault(vault)   # None gelirse kendi açar, dolu gelirse aynen döner
"""

from __future__ import annotations

import logging
from getpass import getpass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.modules.password_manager.service import VaultService

logger = logging.getLogger(__name__)

_VAULT_PATH = Path(__file__).parent.parent / "data" / "vault.dat"


def require_vault(vault: "VaultService | None" = None) -> "VaultService | None":
    """Vault örneği sağlanmamışsa kullanıcıdan master password alarak açar.

    vault_helper.resolve_vault() ile aynı işlevi görür; o fonksiyon tercih edilmeli.
    Fark: Bu fonksiyon hatalı şifrede None döner (resolve_vault tekrar sorar).

    Args:
        vault: main.py'den gelen VaultService örneği ya da None.

    Returns:
        Açık VaultService örneği, ya da kimlik doğrulama başarısızsa None.
    """
    if vault is not None:
        return vault

    # Standalone mod: modül doğrudan çalıştırılıyor
    from app.modules.password_manager.service import VaultService

    v = VaultService(str(_VAULT_PATH))
    while True:
        master = getpass("Master Password: ")
        if v.authenticate(master):
            logger.info("Vault standalone modda açıldı.")
            return v
        print("  Yanlış master password. Tekrar deneyin.")
        again = input("  Tekrar denemek ister misiniz? (e/h): ").strip().lower()
        if again != "e":
            logger.warning("Standalone modda vault açılamadı.")
            return None

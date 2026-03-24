"""
app/modules/network_backup/module.py
─────────────────────────────────────
Çalışma modları:
  - main.py üzerinden : selected.run(vault)
  - Doğrudan          : python -m app.modules.network_backup.module
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from app.core.base_module import BaseModule
from app.common.utils import clear_screen
from app.common.vault_helper import resolve_vault
from .service import backup_menu

if TYPE_CHECKING:
    from app.modules.password_manager.service import VaultService

logger = logging.getLogger(__name__)


class NetworkBackupModule(BaseModule):
    """Ağ cihazlarının konfigürasyon yedeğini alan modül."""

    def info(self) -> dict[str, str]:
        return {
            "name": "Network Backup",
            "description": "Ağ cihazlarının konfigürasyonunu yedekler.",
        }

    def run(self, vault: VaultService | None = None) -> None:
        clear_screen()
        v = resolve_vault(vault)
        backup_menu(v.vault)


if __name__ == "__main__":
    NetworkBackupModule().run()

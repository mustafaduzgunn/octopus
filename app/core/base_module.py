"""
app/core/base_module.py
───────────────────────
Her plugin modülünün implement etmesi gereken sözleşme (ABC).

Çalışma modları:
  1. Ana uygulama (main.py) üzerinden:
       selected.run(vault)
     → main.py vault'u bir kez açar, modüle iletir.

  2. Modül doğrudan çalıştırıldığında:
       python -m app.modules.network_backup.module
     → run() vault=None ile çağrılır, modül kendi vault'unu açar.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.modules.password_manager.service import VaultService


class BaseModule(ABC):
    """Octopus plugin modülleri için soyut taban sınıfı."""

    @abstractmethod
    def info(self) -> dict[str, str]:
        """Modül metadata'sını döndürür.

        Returns:
            dict: En az 'name' anahtarını içeren sözlük.
        """

    @abstractmethod
    def run(self, vault: VaultService | None = None) -> None:
        """Modülün ana işlevini çalıştırır.

        Args:
            vault: main.py'den iletilen açık VaultService örneği.
                   None ise modül vault'u kendi açar (standalone mod).
        """

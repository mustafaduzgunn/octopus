"""
app/core/module_loader.py
─────────────────────────
app/modules/ altındaki paketleri tarar, BaseModule'u implement eden
somut sınıfları bulur ve örnek oluşturarak döndürür.
"""

import inspect
import importlib
import logging
import pkgutil

from app.core.base_module import BaseModule

logger = logging.getLogger(__name__)


def load_modules() -> list[BaseModule]:
    """Tüm geçerli modülleri yükler ve döndürür."""
    modules: list[BaseModule] = []
    package_name = "app.modules"

    try:
        package = importlib.import_module(package_name)
    except ImportError as exc:
        logger.error("Modül paketi yüklenemedi: %s", exc)
        return modules

    for _, module_name, is_pkg in pkgutil.iter_modules(package.__path__):
        if not is_pkg:
            continue

        full_path = f"{package_name}.{module_name}.module"
        try:
            mod = importlib.import_module(full_path)

            # BaseModule'u implement eden somut sınıfı bul
            found = False
            for _, cls in inspect.getmembers(mod, inspect.isclass):
                if (
                    issubclass(cls, BaseModule)
                    and cls is not BaseModule
                    and cls.__module__ == mod.__name__
                ):
                    modules.append(cls())
                    found = True
                    break

            if not found:
                logger.warning(
                    "%s içinde BaseModule alt sınıfı bulunamadı", full_path
                )

        except Exception as exc:
            logger.error("Modül yüklenemedi (%s): %s", module_name, exc)
            print(f"[UYARI] Modül yüklenemedi ({module_name}): {exc}")

    return modules

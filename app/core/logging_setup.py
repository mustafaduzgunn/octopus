"""
app/core/logging_setup.py
─────────────────────────
Uygulamanın tek logging yapılandırma noktası.
main.py içinde bir kez çağrılır; diğer modüller
sadece  logging.getLogger(__name__)  kullanır.
"""

import logging
from pathlib import Path


def configure_logging(log_dir: Path | None = None) -> None:
    """Root logger'ı yapılandırır.  Yalnızca bir kez çağrılmalı."""
    if log_dir is None:
        log_dir = Path(__file__).parent.parent / "logs"

    log_dir.mkdir(parents=True, exist_ok=True)

    root = logging.getLogger()
    if root.handlers:          # Zaten yapılandırılmışsa tekrar ekleme
        return

    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Dosyaya yaz
    file_handler = logging.FileHandler(
        log_dir / "octopus.log", encoding="utf-8"
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    root.setLevel(logging.DEBUG)
    root.addHandler(file_handler)

"""
app/modules/password_manager/service.py
───────────────────────────────────────
Şifreli vault yönetimi.

DÜZELTMELER (v3):
  - Tüm metod imzalarına PEP 484 tip annotasyonları eklendi.
  - derive_key() → _derive_key() (internal, dışa açılmamalı).
  - Docstring'ler eklendi.
  - Diğer modüllerle tutarlı pathlib / Path stili.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_SIZE: int = 16
PBKDF2_ITERATIONS: int = 200_000


class VaultService:
    """PBKDF2 + Fernet ile şifrelenmiş kasa yöneticisi.

    Kullanım:
        vault = VaultService("app/data/vault.dat")
        if vault.authenticate("master_pass"):
            vault.add("github", {"username": "ali", "password": "gizli"})
    """

    def __init__(self, vault_path: str) -> None:
        self.vault_path: str = vault_path
        self.vault: dict = {}
        self._fernet: Fernet | None = None
        self._salt: bytes | None = None

    # ── İç yardımcılar ──────────────────────────────────────

    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        """PBKDF2-HMAC-SHA256 ile şifreden Fernet anahtarı üretir.

        Args:
            password: Master şifre (düz metin).
            salt:     16 byte rastgele tuz.

        Returns:
            URL-safe base64 kodlanmış 32 byte anahtar.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
            backend=default_backend(),
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    # ── Kimlik doğrulama ────────────────────────────────────

    def authenticate(self, master_password: str) -> bool:
        """Vault dosyasını açar; yoksa yeni, boş vault oluşturur.

        Args:
            master_password: Kullanıcı tarafından girilen master şifre.

        Returns:
            True şifre doğruysa (veya vault yeni oluşturulduysa),
            False şifre yanlışsa.
        """
        if not os.path.exists(self.vault_path):
            Path(self.vault_path).parent.mkdir(parents=True, exist_ok=True)
            self._salt = os.urandom(SALT_SIZE)
            key = self._derive_key(master_password, self._salt)
            self._fernet = Fernet(key)
            self.vault = {}
            return True

        file_data = Path(self.vault_path).read_bytes()
        self._salt = file_data[:SALT_SIZE]
        encrypted = file_data[SALT_SIZE:]

        key = self._derive_key(master_password, self._salt)
        self._fernet = Fernet(key)

        try:
            decrypted = self._fernet.decrypt(encrypted)
            self.vault = json.loads(decrypted.decode())
            return True
        except (InvalidToken, json.JSONDecodeError):
            self._fernet = None
            return False

    # ── Veri işlemleri ──────────────────────────────────────

    def save(self) -> None:
        """Vault içeriğini şifreleyerek diske yazar.

        Raises:
            RuntimeError: authenticate() çağrılmamışsa.
        """
        if self._fernet is None or self._salt is None:
            raise RuntimeError("Vault açılmadan kayıt yapılamaz.")
        data = json.dumps(self.vault).encode()
        encrypted = self._fernet.encrypt(data)
        Path(self.vault_path).write_bytes(self._salt + encrypted)

    def add(self, service: str, data: dict) -> None:
        """Yeni servis kaydı ekler ve vault'u kaydeder.

        Args:
            service: Servis adı (anahtar), ör. "github".
            data:    Kayıt içeriği, ör. {"username": ..., "password": ...}.
        """
        self.vault[service] = data
        self.save()

    def delete(self, service: str) -> bool:
        """Servis kaydını siler.

        Args:
            service: Silinecek servis adı.

        Returns:
            True silme başarılıysa, False kayıt bulunamazsa.
        """
        if service in self.vault:
            del self.vault[service]
            self.save()
            return True
        return False

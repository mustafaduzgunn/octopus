"""
app/modules/password_manager/settings.py
─────────────────────────────────────────
Şifre üretim ayarları ve üretici.

DÜZELTME: random.choices() → secrets.choice()
  random modülü kriptografik açıdan güvenli değil (Mersenne Twister).
  secrets modülü OS'un CSPRNG'ini kullanır.
"""

import json
import os
import secrets
import string

default_settings: dict = {
    "length": 12,
    "turkish_characters": False,
    "use_special_characters": True,
    "custom_special_characters": "%!.*@",
    "include_uppercase": True,
    "include_lowercase": True,
    "include_digits": True,
    "exclude_characters": "l1I0O",
    "required_characters": "",
}


class PasswordSettings:
    """Şifre üretim ayarlarını yönetir."""

    def __init__(self, settings_path: str) -> None:
        self.settings_path = settings_path
        self.settings = self._load()

    def _load(self) -> dict:
        if os.path.exists(self.settings_path):
            with open(self.settings_path, encoding="utf-8") as fh:
                return json.load(fh)
        return default_settings.copy()

    def save(self) -> None:
        os.makedirs(os.path.dirname(self.settings_path), exist_ok=True)
        with open(self.settings_path, "w", encoding="utf-8") as fh:
            json.dump(self.settings, fh, ensure_ascii=False, indent=4)

    def generate(self) -> str:
        """Ayarlara göre kriptografik olarak güvenli şifre üretir."""
        s = self.settings
        pool: list[str] = []

        if s.get("include_lowercase"):
            pool.extend(string.ascii_lowercase)
        if s.get("include_uppercase"):
            pool.extend(string.ascii_uppercase)
        if s.get("include_digits"):
            pool.extend(string.digits)
        if s.get("use_special_characters"):
            chars = s.get("custom_special_characters") or string.punctuation
            pool.extend(chars)
        if s.get("turkish_characters"):
            pool.extend("çğıöşüÇĞİÖŞÜ")

        excluded = set(s.get("exclude_characters", ""))
        pool = [c for c in pool if c not in excluded]

        if not pool:
            return "[HATA] Hiçbir karakter türü seçilmedi!"

        required = list(s.get("required_characters", ""))
        length: int = s.get("length", 12)

        if len(required) > length:
            return "[HATA] Zorunlu karakterler şifre uzunluğunu aşıyor!"

        # Kalan pozisyonları CSPRNG ile doldur
        password = required + [secrets.choice(pool) for _ in range(length - len(required))]
        # secrets.SystemRandom ile karıştır
        rng = secrets.SystemRandom()
        rng.shuffle(password)

        return "".join(password)

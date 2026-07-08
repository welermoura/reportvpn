import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.db import models

_fernet = None


def _get_fernet():
    global _fernet
    if _fernet is None:
        key = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
        _fernet = Fernet(base64.urlsafe_b64encode(key))
    return _fernet


PREFIX = 'enc:'


def encrypt(value: str) -> str:
    if not value:
        return value
    return PREFIX + _get_fernet().encrypt(value.encode()).decode()


def decrypt(value: str) -> str:
    if not value or not value.startswith(PREFIX):
        return value
    try:
        return _get_fernet().decrypt(value[len(PREFIX):].encode()).decode()
    except (InvalidToken, Exception):
        return value


class EncryptedCharField(models.CharField):
    """CharField that encrypts values at rest using Fernet (AES-128-CBC + HMAC).
    The key is derived from Django SECRET_KEY. Stored values are prefixed with
    'enc:' so plain-text legacy data is preserved until re-saved."""

    def from_db_value(self, value, expression, connection):
        return decrypt(value) if value else value

    def to_python(self, value):
        return decrypt(value) if value and value.startswith(PREFIX) else value

    def get_prep_value(self, value):
        value = super().get_prep_value(value)
        if not value or value.startswith(PREFIX):
            return value
        return encrypt(value)

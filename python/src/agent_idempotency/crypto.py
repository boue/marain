"""AES-256-GCM for stored snapshots and results."""

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from agent_idempotency.canonical import canonical_dumps, parse_json_value
from agent_idempotency.errors import ConfigError


def parse_record_key(text: str | None) -> bytes | None:
    if text is None or text == "":
        return None
    try:
        key = bytes.fromhex(text)
    except ValueError as exc:
        raise ConfigError("IDEMPOTENCY_RECORD_KEY must be 64 hex characters") from exc
    if len(key) != 32:
        raise ConfigError("IDEMPOTENCY_RECORD_KEY must be 32 bytes")
    return key


def seal(key: bytes, nonce: bytes, token: str, obj: dict) -> dict:
    ciphertext = AESGCM(key).encrypt(nonce, canonical_dumps(obj).encode("utf-8"), token.encode("utf-8"))
    return {
        "ct": base64.b64encode(ciphertext).decode("ascii"),
        "enc": "aes-256-gcm",
        "nonce": base64.b64encode(nonce).decode("ascii"),
    }


def encrypt(key: bytes | None, token: str, obj: dict) -> dict:
    if key is None:
        return obj
    if len(key) != 32:
        raise ConfigError("record key must be 32 bytes")
    return seal(key, os.urandom(12), token, obj)


def decrypt(key: bytes | None, token: str, obj: dict) -> dict:
    if not isinstance(obj, dict) or obj.get("enc") != "aes-256-gcm":
        return obj
    if key is None or len(key) != 32:
        raise ConfigError("stored record is encrypted and IDEMPOTENCY_RECORD_KEY is missing")
    nonce = base64.b64decode(obj["nonce"])
    ciphertext = base64.b64decode(obj["ct"])
    plain = AESGCM(key).decrypt(nonce, ciphertext, token.encode("utf-8"))
    value = parse_json_value(plain.decode("utf-8"))
    if not isinstance(value, dict):
        raise ConfigError("encrypted record is not an object")
    return value

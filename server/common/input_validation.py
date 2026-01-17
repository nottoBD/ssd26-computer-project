# server/common/input_validation.py
import json
import re
import base64
import binascii
from datetime import datetime
from django.utils import timezone

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

class InputError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status

def parse_json_body(request, max_bytes: int = 200_000) -> dict:
    raw = request.body or b""
    if len(raw) > max_bytes:
        raise InputError("Request body too large", 413)
    try:
        obj = json.loads(raw.decode("utf-8") if isinstance(raw, (bytes, bytearray)) else raw)
    except Exception:
        raise InputError("Invalid JSON", 400)
    if not isinstance(obj, dict):
        raise InputError("JSON body must be an object", 400)
    return obj

def clean_str(v, *, strip=True, lower=False) -> str:
    if not isinstance(v, str):
        raise InputError("Expected string", 400)
    if strip:
        v = v.strip()
    if lower:
        v = v.lower()
    # bloque caractères de contrôle
    if any(ord(c) < 32 for c in v):
        raise InputError("Invalid characters in input", 400)
    return v

def require_str(data: dict, key: str, *, max_len: int, strip=True, lower=False) -> str:
    if key not in data:
        raise InputError(f"Missing field: {key}", 400)
    v = clean_str(data[key], strip=strip, lower=lower)
    if len(v) == 0:
        raise InputError(f"Empty field: {key}", 400)
    if len(v) > max_len:
        raise InputError(f"Field too long: {key}", 400)
    return v

def optional_str(data: dict, key: str, *, max_len: int, default="", strip=True, lower=False) -> str:
    if key not in data or data[key] is None:
        return default
    v = clean_str(data[key], strip=strip, lower=lower)
    if len(v) > max_len:
        raise InputError(f"Field too long: {key}", 400)
    return v

def require_email(data: dict, key="email") -> str:
    email = require_str(data, key, max_len=254, strip=True, lower=True)
    if not EMAIL_RE.match(email):
        raise InputError("Invalid email format", 400)
    return email

def require_choice(data: dict, key: str, allowed: set[str]) -> str:
    v = require_str(data, key, max_len=32, strip=True, lower=False)
    if v not in allowed:
        raise InputError(f"Invalid value for {key}", 400)
    return v

def parse_iso_datetime(value: str, *, max_skew_seconds: int | None = None) -> datetime:
    if not isinstance(value, str) or len(value) > 64:
        raise InputError("Invalid timestamp format", 400)
    try:
        dt = datetime.fromisoformat(value)
    except Exception:
        raise InputError("Invalid timestamp format", 400)
    # normalise en aware si besoin
    if timezone.is_naive(dt):
        dt = timezone.make_aware(dt, timezone.get_current_timezone())
    if max_skew_seconds is not None:
        now = timezone.now()
        if abs((now - dt).total_seconds()) > max_skew_seconds:
            raise InputError("Request timestamp too old", 400)
    return dt

def b64decode_limited(b64: str, *, max_decoded: int) -> bytes:
    if not isinstance(b64, str):
        raise InputError("Expected base64 string", 400)
    if len(b64) > (max_decoded * 4 // 3) + 32:
        raise InputError("Payload too large", 413)
    try:
        raw = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError):
        raise InputError("Invalid base64", 400)
    if len(raw) > max_decoded:
        raise InputError("Decoded payload too large", 413)
    return raw

def hex_to_bytes_limited(hex_str: str, *, exact_len: int | None = None, max_len: int = 4096) -> bytes:
    if not isinstance(hex_str, str):
        raise InputError("Expected hex string", 400)
    hex_str = hex_str.strip()
    if len(hex_str) > max_len:
        raise InputError("Hex payload too large", 413)
    try:
        raw = bytes.fromhex(hex_str)
    except ValueError:
        raise InputError("Invalid hex", 400)
    if exact_len is not None and len(raw) != exact_len:
        raise InputError("Invalid key length", 400)
    return raw

def require_pem_cert(data: dict, key: str, *, max_len: int = 20_000) -> str:
    pem = require_str(data, key, max_len=max_len, strip=False, lower=False)
    if "BEGIN CERTIFICATE" not in pem or "END CERTIFICATE" not in pem:
        raise InputError("Invalid certificate PEM", 400)
    return pem


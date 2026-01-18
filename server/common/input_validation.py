import json
import re
import base64
import binascii
from datetime import datetime
from django.utils import timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

# Small input-validation helpers used by API endpoints
# Goal: fail fast with clear 4xx errors and size limits before doing heavier work
# Keeps validation consistent across views
# 
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Raised when user input is invalid
# Carries an HTTP-ish status so views can map errors to proper responses
class InputError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status

# Reads request.body as JSON with a hard size cap
# Only accepts JSON objects (dict) since endpoints expect key/value payloads
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

# Normalizes a string input (trim, optional lowercasing)
# Rejects control characters to avoid log injection and weird parsing edge cases
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

# Required string field with length constraints
# Gives predictable error messages for missing/empty/too long fields
def require_str(data: dict, key: str, *, max_len: int, strip=True, lower=False) -> str:
    if key not in data:
        raise InputError(f"Missing field: {key}", 400)
    v = clean_str(data[key], strip=strip, lower=lower)
    if len(v) == 0:
        raise InputError(f"Empty field: {key}", 400)
    if len(v) > max_len:
        raise InputError(f"Field too long: {key}", 400)
    return v


# Optional string field with default fallback
# Still enforces max length when provided
def optional_str(data: dict, key: str, *, max_len: int, default="", strip=True, lower=False) -> str:
    if key not in data or data[key] is None:
        return default
    v = clean_str(data[key], strip=strip, lower=lower)
    if len(v) > max_len:
        raise InputError(f"Field too long: {key}", 400)
    return v

# Email field validation, normalizes to lowercase
# Regex is intentionally simple, backend still treats email as an identifier not a guarantee of deliverability
def require_email(data: dict, key="email") -> str:
    email = require_str(data, key, max_len=254, strip=True, lower=True)
    if not EMAIL_RE.match(email):
        raise InputError("Invalid email format", 400)
    return email

# Validates that a string field is one of a known set of values
# Useful for enums like role/type/status coming from the client
def require_choice(data: dict, key: str, allowed: set[str]) -> str:
    v = require_str(data, key, max_len=32, strip=True, lower=False)
    if v not in allowed:
        raise InputError(f"Invalid value for {key}", 400)
    return v


# Parses ISO timestamps and normalizes to timezone-aware datetime
# Optional skew check is used to limit replay windows for signed requests
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

# Base64 decoder with size guards
# Protects against oversized payloads and avoids allocating huge buffers
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

# Hex decoder with length limits
# Can enforce exact byte length for keys (ex: X25519 pubkey should be 32 bytes)
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

# Basic PEM sanity check for certificates
# Does not validate trust chain here, only ensures the payload looks like a cert
def require_pem_cert(data: dict, key: str, *, max_len: int = 20_000) -> str:
    pem = require_str(data, key, max_len=max_len, strip=False, lower=False)
    if "BEGIN CERTIFICATE" not in pem or "END CERTIFICATE" not in pem:
        raise InputError("Invalid certificate PEM", 400)
    return pem



def parse_metadata(request, user):
    header = request.headers.get('X-Metadata')
    if not header:
        return {}
    
    parts = header.split('|')
    if len(parts) > 2:
        return {}
    
    metadata_b64 = parts[0]
    try:
        padding = '==' * ((4 - len(metadata_b64) % 4) % 4)
        metadata_json_bytes = base64.b64decode((metadata_b64 + padding).encode('ascii'))
        metadata_json = metadata_json_bytes.decode('utf-8')
        metadata = json.loads(metadata_json)
    except Exception:
        return {}
    
    if 'timestamp' not in metadata:
        return {}  # Ignore if missing
    
    try:
        parse_iso_datetime(metadata['timestamp'], max_skew_seconds=30)
    except:
        return {}
    
    if 'size' in metadata:
        if not isinstance(metadata['size'], int) or metadata['size'] < 0:
            del metadata['size']  # Ignore invalid
    
    if 'privileges' in metadata and (not isinstance(metadata['privileges'], list) or not all(isinstance(p, str) for p in metadata['privileges'])):
        del metadata['privileges']
    
    # treeDepth: Optional int >=0
    if 'treeDepth' in metadata and (not isinstance(metadata['treeDepth'], int) or metadata['treeDepth'] < 0):
        del metadata['treeDepth']
    
    if len(parts) == 2:
        if user is not None:
            sig_hex = parts[1]
            try:
                sig = bytes.fromhex(sig_hex)
                pub = Ed25519PublicKey.from_public_bytes(bytes(user.signing_public_key))
                pub.verify(sig, metadata_json.encode('utf-8'))
            except (InvalidSignature, ValueError):
                return {}  # Ignore invalid sig instead of raise
    
    return metadata

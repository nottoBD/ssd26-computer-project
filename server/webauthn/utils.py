from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity
from django.conf import settings
import os
from base64 import urlsafe_b64decode

rp_id = os.getenv("RP_ID", "healthsecure.local")
rp_name = "HealthSecure"

rp = PublicKeyCredentialRpEntity(id=rp_id, name=rp_name)
server = Fido2Server(rp, attestation="none")  # "none" = maximum compatibility & privacy

def get_server():
    return server

def base64url_decode(s: str) -> bytes:
    """Decode base64url string to bytes"""
    s = s.encode() if isinstance(s, str) else s
    return urlsafe_b64decode(s + b'=' * (-len(s) % 4))

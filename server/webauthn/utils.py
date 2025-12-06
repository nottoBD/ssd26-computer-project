from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity
from django.conf import settings
import os

rp_id = os.getenv("RP_ID", "localhost")
rp_name = "HealthSecure Project"

rp = PublicKeyCredentialRpEntity(id=rp_id, name=rp_name)
server = Fido2Server(rp, attestation="none")  # "none" = maximum compatibility & privacy

def get_server():
    return server


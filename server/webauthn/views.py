import json
import uuid
from base64 import urlsafe_b64decode, urlsafe_b64encode

from django.http import JsonResponse
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.contrib.auth import login

from fido2.webauthn import PublicKeyCredentialRpEntity, AttestedCredentialData, CollectedClientData, AttestationObject, AuthenticatorData
from fido2.server import Fido2Server
from fido2 import cbor
from fido2.utils import websafe_encode, websafe_decode
import cbor2
from hashlib import sha256
from accounts.models import User, PatientRecord
from .models import WebAuthnCredential

# Using sha256 of a unique string → always the same salts → same PRF output on every device for the same credential
 # This guarantees stable KEK across sessions and synced devices (Apple/Google/1Password/Bitwarden all sync the PRF secret)
 # Using two salts + XOR = maximum compatibility (Apple sometimes only returns one, but XOR still works if both present)
PRF_SALT_FIRST = sha256(b"HealthSecure Project - PRF salt v1 - first").digest()
PRF_SALT_SECOND = sha256(b"HealthSecure Project - PRF salt v1 - second").digest()

rp = PublicKeyCredentialRpEntity(id="healthsecure.local", name="HealthSecure Project")
server = Fido2Server(rp, attestation="none")

def to_serializable(obj):
    if isinstance(obj, bytes):
        return websafe_encode(obj)
    if isinstance(obj, dict):
        return {k: to_serializable(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [to_serializable(v) for v in obj]
    return obj


@method_decorator(csrf_exempt, name="dispatch")
class StartRegistration(View):
    def post(self, request):
        data = json.loads(request.body)

        email = data["email"].strip().lower()
        if User.objects.filter(email=email).exists():
            return JsonResponse({"error": "Email already taken"}, status=400)

        user = User.objects.create_user(
            email=email,
            first_name=data["first_name"],
            last_name=data["last_name"],
            type=data["type"],
            date_of_birth=data.get("date_of_birth"),
            medical_organization=data.get("medical_organization", ""),
        )
        user.is_active = False
        user.save()

        if user.type == User.Type.PATIENT:
            PatientRecord.objects.create(patient=user)

        # Base call
        options, state = server.register_begin(
            user={
                "id": str(user.id).encode(),
                "name": user.email,
                "displayName": f"{user.first_name} {user.last_name}",
            },
            credentials=[],
            user_verification="required",
        )

        # discoverable credential
        pk_options = dict(options.public_key)

        pk_options["authenticatorSelection"] = {
            "requireResidentKey": True,
            "residentKey": "required",
            "userVerification": "required",
        }
        pk_options["extensions"] = {"prf": {}}

        request.session["reg_state"] = state
        request.session["reg_user_id"] = str(user.id)

        return JsonResponse(to_serializable(pk_options))


@method_decorator(csrf_exempt, name="dispatch")
class FinishRegistration(View):
    def post(self, request):
        state = request.session.get("reg_state")
        user_id = request.session.get("reg_user_id")
        if not state or not user_id:
            return JsonResponse({"error": "No registration in progress"}, status=400)

        user = User.objects.get(id=uuid.UUID(user_id))
        response = json.loads(request.body)

        client_data_json = websafe_decode(response["response"]["clientDataJSON"])
        attestation_object = websafe_decode(response["response"]["attestationObject"])

        client_data = CollectedClientData(client_data_json)
        att_obj = AttestationObject(attestation_object)

        auth_data = server.register_complete(state, client_data, att_obj)  # returns AuthenticatorData in fido2==1.1.3
        prf_enabled = response.get("clientExtensionResults", {}).get("prf", {}).get("enabled", False)

        WebAuthnCredential.objects.create(
            user=user,
            credential_id=auth_data.credential_data.credential_id,
            public_key=cbor2.dumps(auth_data.credential_data.public_key),  # COSE key dict to CBOR bytes
            name=data.get('device_name', 'Unnamed Device'),
            sign_count=auth_data.counter,  # fido2 1.1.3
            transports=response.get("transports", []),
            prf_enabled=prf_enabled,
        )

        user.is_active = True
        user.save()
        login(request, user)

        del request.session["reg_state"]
        del request.session["reg_user_id"]

        return JsonResponse({"status": "OK", "prf_enabled": prf_enabled})


@method_decorator(csrf_exempt, name="dispatch")
class StartAuthentication(View):
    def post(self, request):
        # Discoverable credentials only (no email needed)
        options, state = server.authenticate_begin(
            credentials=[],  # discoverable/resident keys
            user_verification="required",
            # 2 salts required by APPLE
            extensions={"prf": {"eval": {"first": PRF_SALT_FIRST, "second": PRF_SALT_SECOND}}},
        )

        pk_options = dict(options.public_key)

        request.session["auth_state"] = state

        return JsonResponse(to_serializable(pk_options))


@method_decorator(csrf_exempt, name="dispatch")
class FinishAuthentication(View):
    def post(self, request):
        state = request.session.get("auth_state")
        if not state:
            return JsonResponse({"error": "No authentication in progress"}, status=400)

        response = json.loads(request.body)
        credential_id = websafe_decode(response["rawId"])
        credential = WebAuthnCredential.objects.get(credential_id=credential_id)
        client_data_json = websafe_decode(response["response"]["clientDataJSON"])
        authenticator_data = websafe_decode(response["response"]["authenticatorData"])
        signature = websafe_decode(response["response"]["signature"])
        client_data = CollectedClientData(client_data_json)
        authenticator_data_obj = AuthenticatorData(authenticator_data)
        #print(f"Counter brut: {authenticator_data_obj.counter}")
        #print(f"Counter stocké en DB: {credential.sign_count}")

        auth_data = server.authenticate_complete(
            state,
            [credential.get_credential_data()],
            credential_id,
            client_data,
            authenticator_data_obj,
            signature,
            )

        if not authenticator_data_obj.is_user_verified:
                    raise ValueError("User verification required")

        # ----- Sign count check – protect against cloned authenticators -----
        # Most of password managers let count to 0 https://github.com/bitwarden/clients/pull/8024#top
        # Hardware key like yubikey use the counter
        # auth_date does not countains a counter attribut but the authenticator_data_obj does
        # # TODO: add logging for anomalies
        if authenticator_data_obj.counter != 0 and authenticator_data_obj.counter <= credential.sign_count:
            raise ValueError("Possible cloned authenticator detected (sign count did not increase)")
        credential.sign_count = authenticator_data_obj.counter
        credential.save()

        # ----- PRF extension results (multi-device ready KEK) -----
        ext_results = response.get("clientExtensionResults", {}).get("prf", {}).get("results", {})
        prf_first = ext_results.get("first")
        prf_second = ext_results.get("second")

        if prf_first and prf_second:
            # Apple/Google compatible XOR both values for maximum entropy
            prf_bytes = bytes(a ^ b for a, b in zip(prf_first, prf_second))
        elif prf_first:
            prf_bytes = prf_first
        elif prf_second:
            prf_bytes = prf_second
        else:
            prf_bytes = None  # fallback to no KEK on very old authenticators


        prf_hex = prf_bytes.hex() if prf_bytes else None

        login(request, credential.user)
        del request.session["auth_state"]

        return JsonResponse({
            "status": "OK",
            "prf_hex": prf_hex, # used to derive/store encrypted X25519 key
        })

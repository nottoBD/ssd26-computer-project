import json
import uuid
from base64 import urlsafe_b64decode, urlsafe_b64encode

from django.http import JsonResponse
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.contrib.auth import login

from fido2.webauthn import PublicKeyCredentialRpEntity, AttestedCredentialData, CollectedClientData, AttestationObject
from fido2.server import Fido2Server
from fido2 import cbor
from fido2.utils import websafe_encode, websafe_decode

from accounts.models import User, PatientRecord
from .models import WebAuthnCredential

rp = PublicKeyCredentialRpEntity(id="localhost", name="HealthSecure Project")

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
            user_verification="preferred",
        )

        # discoverable credential
        pk_options = dict(options.public_key)

        pk_options["authenticatorSelection"] = {
            "requireResidentKey": True,
            "residentKey": "required",
            "userVerification": "preferred",
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

        auth_data = server.register_complete(state, client_data, att_obj)

        prf_enabled = response.get("clientExtensionResults", {}).get("prf", {}).get("enabled", False)

        WebAuthnCredential.objects.create(
            user=user,
            credential_id=auth_data.credential_data.credential_id,
            public_key=auth_data.credential_data.public_key,
            sign_count=auth_data.credential_data.sign_count,
            transports=response.get("transports", []),
            prf_enabled=prf_enabled,
        )

        user.is_active = True
        user.save()
        login(request, user)

        request.session.flush()

        return JsonResponse({"status": "OK", "prf_enabled": prf_enabled})


@method_decorator(csrf_exempt, name="dispatch")
class StartAuthentication(View):
    def post(self, request):
        # Discoverable credentials only (no email needed)
        options, state = server.authenticate_begin(
            credentials=[],  # discoverable/resident keys
            user_verification="preferred",
            extensions={"prf": {"eval": {"first": b"\x00" * 32}}},
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

        server.authenticate_complete(
            state,
            [credential.get_credential_data()],
            credential_id,
            client_data.hash,
            authenticator_data,
            signature,
        )

        # sign count
        credential.sign_count = auth_data.sign_count
        credential.save()

        # PRF result
        prf_hex = None
        ext_results = response.get("clientExtensionResults", {}).get("prf", {}).get("results", {})
        if "first" in ext_results:
            prf_hex = urlsafe_b64decode(ext_results["first"] + "==").hex()

        login(request, credential.user)
        request.session.flush()

        return JsonResponse({
            "status": "OK",
            "prf_hex": prf_hex or None,
        })

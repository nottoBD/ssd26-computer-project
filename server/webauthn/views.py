import cbor2
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.views import View
from django.contrib.auth import login
from accounts.models import User, PatientRecord
from .utils import get_server
from .models import WebAuthnCredential

@method_decorator(csrf_exempt, name="dispatch")
class StartRegistration(View):
    def post(self, request):
        data = cbor2.loads(request.body)  # expect user data + optional credential name
        # data = {"email": "", "first_name": "", "last_name": "", "type": "patient|doctor", "date_of_birth": "", "medical_organization": ""}

        # Validate & create inactive user
        try:
            user = User.objects.create_user(
                email=data["email"],
                first_name=data["first_name"],
                last_name=data["last_name"],
                type=data["type"],
                date_of_birth=data.get("date_of_birth"),
                medical_organization=data.get("medical_organization", ""),
            )
            user.is_active = False  # activate only after successful credential
            user.save()

            if user.type == User.Type.PATIENT:
                PatientRecord.objects.create(patient=user)  # auto-create record
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)

        # Start WebAuthn registration
        options, state = get_server().register_begin(
            {
                "id": user.email.encode(),  # can be anything unique
                "name": user.email,
                "displayName": f"{user.first_name} {user.last_name}",
            },
            [],  # existing credentials (none yet)
            user_verification="preferred",
            extensions={"prf": True},  # request PRF support (modern standard)
        )

        request.session["webauthn_registration_state"] = state
        request.session["webauthn_register_user_id"] = user.id

        return JsonResponse(options)


@method_decorator(csrf_exempt, name="dispatch")
class FinishRegistration(View):
    def post(self, request):
        state = request.session.get("webauthn_registration_state")
        user_id = request.session.get("webauthn_register_user_id")
        if not state or not user_id:
            return JsonResponse({"error": "No registration in progress"}, status=400)

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return JsonResponse({"error": "Invalid session"}, status=400)

        client_data = cbor2.loads(request.body)

        auth_data = get_server().register_complete(
            state,
            client_data,
            [b"none"],  # expected attestation types
        )

        # Check PRF support
        prf_extension = auth_data.extension_results.get("prf", {})
        prf_enabled = prf_extension.get("enabled", False)

        WebAuthnCredential.objects.create(
            user=user,
            credential_id=auth_data.credential_data.credential_id,
            public_key=auth_data.credential_data.public_key,
            sign_count=auth_data.credential_data.sign_count,
            transports=list(auth_data.credential_data.transports or []),
            prf_enabled=prf_enabled,
        )

        user.is_active = True
        user.save()

        # Auto-login after registration
        login(request, user, backend="django.contrib.auth.backends.ModelBackend")

        # Clean session
        del request.session["webauthn_registration_state"]
        del request.session["webauthn_register_user_id"]

        return JsonResponse({
            "status": "OK",
            "prf_enabled": prf_enabled,
        })


@method_decorator(csrf_exempt, name="dispatch")
class StartAuthentication(View):
    def post(self, request):
        # We accept either email or empty (for discoverable credentials)
        import json
        data = json.loads(request.body)
        username = data.get("email", "").strip().lower()

        if username:
            try:
                user = User.objects.get(email=username)
                credentials = user.webauthn_credentials.all()
            except User.DoesNotExist:
                credentials = []
        else:
            credentials = WebAuthnCredential.objects.all()  # allow any discoverable credential

        if not credentials:
            return JsonResponse({"error": "No credentials found"}, status=404)

        options, state = get_server().authenticate_begin(
            [cred.get_credential_data() for cred in credentials],
            user_verification="preferred",
            extensions={"prf": {"eval": {"first": b"\x00"*32}}}  # request PRF salt
        )

        request.session["webauthn_auth_state"] = state
        return JsonResponse(options)


@method_decorator(csrf_exempt, name="dispatch")
class FinishAuthentication(View):
    def post(self, request):
        state = request.session.get("webauthn_auth_state")
        if not state:
            return JsonResponse({"error": "No authentication in progress"}, status=400)

        client_data = cbor2.loads(request.body)

        credential = None
        for cred in WebAuthnCredential.objects.all():
            try:
                auth_data = get_server().authenticate_complete(
                    state,
                    [cred.get_credential_data()],
                    client_data.credential_id,
                    client_data.client_data_hash,
                    client_data.authenticator_data,
                    client_data.signature,
                )
                credential = cred
                break
            except Exception:
                continue

        if not credential:
            return JsonResponse({"error": "Authentication failed"}, status=400)

        # Update sign count
        credential.sign_count = auth_data.sign_count
        credential.save()

        # Extract PRF output if available
        prf_result = None
        ext_results = auth_data.extension_results.get("prf", {})
        if ext_results.get("results"):
            prf_result = ext_results["results"].get("first")
            if prf_result:
                prf_result = bytes(prf_result)

        # Log the user in
        login(request, credential.user, backend="django.contrib.auth.backends.ModelBackend")

        # Clean session
        if "webauthn_auth_state" in request.session:
            del request.session["webauthn_auth_state"]

        return JsonResponse({
            "status": "OK",
            "prf_available": prf_result is not None,
            "prf_hex": prf_result.hex() if prf_result else None,
        })




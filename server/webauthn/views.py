import json
import uuid
import types
import enum
from base64 import urlsafe_b64decode, urlsafe_b64encode

from django.http import JsonResponse
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required

from fido2.webauthn import PublicKeyCredentialRpEntity, AttestedCredentialData, CollectedClientData, AttestationObject, AuthenticatorData
from fido2.server import Fido2Server
from fido2 import cbor
from fido2.utils import websafe_encode, websafe_decode
import cbor2
from hashlib import sha256
from accounts.models import User, PatientRecord
from .models import WebAuthnCredential, AuthenticationLog
import logging
import secrets
from datetime import timedelta
from django.utils import timezone
from .utils import get_server

logger = logging.getLogger(__name__)

# Using sha256 of a unique string → always the same salts → same PRF output on every device for the same credential
 # This guarantees stable KEK across sessions and synced devices (Apple/Google/1Password/Bitwarden all sync the PRF secret)
 # Using two salts + XOR = maximum compatibility (Apple sometimes only returns one, but XOR still works if both present)
PRF_SALT_FIRST = sha256(b"HealthSecure Project - PRF salt v1 - first").digest()
PRF_SALT_SECOND = sha256(b"HealthSecure Project - PRF salt v1 - second").digest()

rp = PublicKeyCredentialRpEntity(id="healthsecure.local", name="HealthSecure Project")
server = get_server()

def to_serializable(obj):
    if isinstance(obj, bytes):
        return websafe_encode(obj)
    if isinstance(obj, dict):
        return {k: to_serializable(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [to_serializable(v) for v in obj]
    if isinstance(obj, enum.Enum):
        return obj.value
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
            "userVerification": "preferred",
        }
        pk_options["extensions"] = {"prf": {}}

        request.session["reg_state"] = state
        request.session["reg_user_id"] = str(user.id)
        request.session["reg_device_name"] = data.get("device_name", "")

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

        credential = WebAuthnCredential.objects.create(
            user=user,
            credential_id=auth_data.credential_data.credential_id,
            public_key=cbor2.dumps(auth_data.credential_data.public_key),  # COSE key dict to CBOR bytes
            name=request.session.get('reg_device_name', 'Unnamed Device'),
            sign_count=auth_data.counter,  # fido2 1.1.3
            transports=response.get("transports", []),
            prf_enabled=prf_enabled,
            aaguid=auth_data.credential_data.aaguid,  # for authenticator type insights
        )

        # Mark as primary if first credential
        if not user.webauthn_credentials.exclude(pk=credential.pk).exists():
            credential.is_primary = True
            credential.save()

        user.is_active = True
        user.save()
        login(request, user)

        del request.session["reg_state"]
        del request.session["reg_user_id"]
        del request.session["reg_device_name"]

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

        cred_log_data = {}  # For logging if credential found

        try:
            credential = WebAuthnCredential.objects.get(credential_id=credential_id)
            cred_log_data = {
                'user': credential.user,
                'device_name': credential.name
            }
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

            # ----- sign count check for clone detection -----
            current_counter = authenticator_data_obj.counter
            if credential.supports_sign_count and current_counter <= credential.sign_count:
                logger.warning(f"Possible clone detected for credential {credential.id} (counter {current_counter} <= {credential.sign_count}) from IP {request.META.get('REMOTE_ADDR')}")
                raise ValueError("Possible cloned authenticator detected")

            # Detect if supports incrementing (set flag)
            if current_counter > credential.sign_count:
                if not credential.supports_sign_count:
                    credential.supports_sign_count = True

            # Log for anomaly detection (expand with metadata like time/size for master note)
            elif current_counter == 0 and credential.sign_count == 0:
                logger.info(f"Software authenticator (no counter) used for user {credential.user.id} from IP {request.META.get('REMOTE_ADDR')}")
            credential.sign_count = current_counter
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
            request.session['used_credential_id'] = websafe_encode(credential.credential_id)
            request.session.pop("auth_state", None)

            # Log success
            AuthenticationLog.objects.create(
                user=credential.user,
                ip_address=request.META.get('REMOTE_ADDR'),
                device_name=credential.name,
                success=True,
                metadata={
                    'request_size': len(request.body),
                    'privileges': 'login',
                    # tree_depth  here for record access
                }
            )
            return JsonResponse({
                "status": "OK",
                "prf_hex": prf_hex, # used to derive/store encrypted X25519 key
            })
        except Exception as e:
            # Log failure
            AuthenticationLog.objects.create(
                user=cred_log_data.get('user'),
                ip_address=request.META.get('REMOTE_ADDR'),
                device_name=cred_log_data.get('device_name', 'Unknown'),
                success=False,
                metadata={
                    'error': str(e),
                    'request_size': len(request.body),
                    'privileges': 'login',
                }
            )
            return JsonResponse({"error": str(e)}, status=400)

    #Approval to add secondary credential (auth with primary only)
@method_decorator(csrf_exempt, name="dispatch")
class StartAddCredentialApproval(View):
    def post(self, request):
        if not request.user.is_authenticated:
            return JsonResponse({"error": "Authentication required"}, status=401)
        primary_cred = WebAuthnCredential.objects.filter(user=request.user, is_primary=True).first()
        if not primary_cred:
            return JsonResponse({"error": "No primary credential found"}, status=400)
        options, state = server.authenticate_begin(
            credentials=[primary_cred.get_credential_data()],
            user_verification="required",
            extensions={"prf": {"eval": {"first": PRF_SALT_FIRST, "second": PRF_SALT_SECOND}}},
        )
        pk_options = dict(options.public_key)
        pk_options['allowCredentials'] = [{
            "type": "public-key",
            "id": websafe_encode(primary_cred.credential_id),
            "transports": primary_cred.transports,
        }]
        request.session["add_cred_approval_state"] = state
        return JsonResponse(to_serializable(pk_options))

@method_decorator(csrf_exempt, name="dispatch")
class FinishAddCredentialApproval(View):
    def post(self, request):
        state = request.session.get("add_cred_approval_state")
        if not state:
            return JsonResponse({"error": "No approval in progress"}, status=400)
        response = json.loads(request.body)
        credential_id = websafe_decode(response["rawId"])
        primary_cred = WebAuthnCredential.objects.filter(user=request.user, is_primary=True).first()
        if credential_id != primary_cred.credential_id:
            return JsonResponse({"error": "Not primary credential"}, status=403)
        credential = primary_cred
        client_data_json = websafe_decode(response["response"]["clientDataJSON"])
        authenticator_data = websafe_decode(response["response"]["authenticatorData"])
        signature = websafe_decode(response["response"]["signature"])
        client_data = CollectedClientData(client_data_json)
        authenticator_data_obj = AuthenticatorData(authenticator_data)
        server.authenticate_complete(
            state,
            [credential.get_credential_data()],
            credential_id,
            client_data,
            authenticator_data_obj,
            signature,
        )
        if not authenticator_data_obj.is_user_verified:
            raise ValueError("User verification required")
        current_counter = authenticator_data_obj.counter
        if credential.supports_sign_count and current_counter <= credential.sign_count:
            logger.warning(f"Possible clone during approval for user {request.user.id}")
            raise ValueError("Possible cloned authenticator detected")
        if current_counter > credential.sign_count:
            if not credential.supports_sign_count:
                credential.supports_sign_count = True
        credential.sign_count = current_counter
        credential.save()

        # Generate one-time add code
        code = secrets.token_hex(16)
        request.user.pending_add_code = code
        request.user.pending_add_expiry = timezone.now() + timedelta(minutes=10)
        request.user.save()

        del request.session["add_cred_approval_state"]
        return JsonResponse({"status": "OK", "add_code": code})


class FinishAddCredential(View):
    def post(self, request):
        state = request.session.get("add_cred_state")
        user_id = request.session.get("add_cred_user_id")
        if not state or not user_id:
            return JsonResponse({"error": "No add in progress"}, status=400)
        try:
            user = User.objects.get(id=uuid.UUID(user_id))
        except User.DoesNotExist:
            return JsonResponse({"error": "User not found"}, status=404)

        response = json.loads(request.body)
        client_data_json = websafe_decode(response["response"]["clientDataJSON"])
        attestation_object = websafe_decode(response["response"]["attestationObject"])
        client_data = CollectedClientData(client_data_json)
        att_obj = AttestationObject(attestation_object)
        auth_data = server.register_complete(state, client_data, att_obj)
        prf_enabled = response.get("clientExtensionResults", {}).get("prf", {}).get("enabled", False)
        credential = WebAuthnCredential.objects.create(
            user=user,
            credential_id=auth_data.credential_data.credential_id,
            public_key=cbor2.dumps(auth_data.credential_data.public_key),
            name=request.session.get('add_cred_device_name', 'Unnamed Device'),
            sign_count=auth_data.counter,
            transports=response.get("transports", []),
            prf_enabled=prf_enabled,
            aaguid=auth_data.credential_data.aaguid,
            is_primary=False,
        )
        del request.session["add_cred_state"]
        del request.session["add_cred_user_id"]
        del request.session["add_cred_device_name"]

        # Auto-login on new device
        login(request, user)
        request.session['used_credential_id'] = websafe_encode(credential.credential_id)

        # Log
        AuthenticationLog.objects.create(
            user=user,
            ip_address=request.META.get('REMOTE_ADDR'),
            device_name=credential.name,
            success=True,
            metadata={'privileges': 'add_device'}
        )

        return JsonResponse({"status": "OK", "prf_enabled": prf_enabled})

@method_decorator(csrf_exempt, name='dispatch')
class StartAddWithCode(View):
    def post(self, request):
        data = json.loads(request.body)
        email = data.get('email', '').strip().lower()
        code = data.get('code', '')
        device_name = data.get('device_name', 'New Device')

        if not email or not code:
            return JsonResponse({"error": "Email and code required"}, status=400)

        try:
            user = User.objects.get(email=email)
            if user.pending_add_code != code or user.pending_add_expiry < timezone.now():
                raise ValueError("Invalid or expired code")

            # Clear code
            user.pending_add_code = None
            user.pending_add_expiry = None
            user.save()

            options, state = server.register_begin(
                user={
                    "id": str(user.id).encode(),
                    "name": user.email,
                    "displayName": f"{user.first_name} {user.last_name}",
                },
                credentials=[c.get_credential_data() for c in user.webauthn_credentials.all()],
                user_verification="required",
            )
            pk_options = dict(options.public_key)
            pk_options["authenticatorSelection"] = {
                "requireResidentKey": True,
                "residentKey": "required",
                "userVerification": "required",
            }
            pk_options["extensions"] = {"prf": {}}
            request.session["add_cred_state"] = state
            request.session["add_cred_user_id"] = str(user.id)
            request.session["add_cred_device_name"] = device_name
            return JsonResponse(to_serializable(pk_options))

        except User.DoesNotExist:
            return JsonResponse({"error": "User not found"}, status=404)
        except ValueError as e:
            return JsonResponse({"error": str(e)}, status=400)

class UserCredentials(View):
    @method_decorator(login_required)
    def get(self, request):
        if not is_primary_device(request):
            return JsonResponse({'error': 'Access restricted to primary device'}, status=403)
        creds = request.user.webauthn_credentials.all()
        return JsonResponse([{
            'id': websafe_encode(cred.credential_id),  # Use websafe_encode for string id
            'name': cred.name,
            'created_at': cred.created_at.isoformat(),
            'prf_enabled': cred.prf_enabled,
            'is_primary': cred.is_primary,
            'supports_sign_count': cred.supports_sign_count
        } for cred in creds], safe=False)

class UserActivity(View):
    @method_decorator(login_required)
    def get(self, request):
        if not is_primary_device(request):
            return JsonResponse({'error': 'Access restricted to primary device'}, status=403)
        logs = AuthenticationLog.objects.filter(user=request.user).order_by('-timestamp')[:50]
        return JsonResponse([{
            'time': log.timestamp.isoformat(),
            'ip': log.ip_address,
            'device_name': log.device_name,
            'success': log.success
        } for log in logs], safe=False)

class DeleteCredential(View):
    @method_decorator(csrf_exempt)
    @method_decorator(login_required)
    def delete(self, request, cred_id):
        if not is_primary_device(request):
            return JsonResponse({'error': 'Access restricted to primary device'}, status=403)
        try:
            cred_id_bin = websafe_decode(cred_id)
            cred = WebAuthnCredential.objects.get(user=request.user, credential_id=cred_id_bin)
            if cred.is_primary:
                return JsonResponse({'error': 'Cannot delete primary device'}, status=403)
            cred.delete()
            return JsonResponse({'status': 'OK'})
        except WebAuthnCredential.DoesNotExist:
            return JsonResponse({'error': 'Credential not found'}, status=404)



@method_decorator(csrf_exempt, name="dispatch")
class AuthStatus(View):
    def get(self, request):
        return JsonResponse({
            'authenticated': request.user.is_authenticated
        })

@method_decorator(csrf_exempt, name="dispatch")
class LogoutView(View):
    def post(self, request):
        if request.user.is_authenticated:
            logout(request)
            # Flush session
            request.session.flush()
            response = JsonResponse({"status": "OK"})
            # Expire cookies client-side, but server already invalidated
            response.delete_cookie('sessionid')
            response.delete_cookie('csrftoken')
            return response
        return JsonResponse({"error": "Not authenticated"}, status=401)

def is_primary_device(request):
    cid = request.session.get('used_credential_id')
    if cid:
        try:
            cred = WebAuthnCredential.objects.get(
                credential_id=websafe_decode(cid),
                user=request.user
            )
            return cred.is_primary
        except WebAuthnCredential.DoesNotExist:
            pass
    return False


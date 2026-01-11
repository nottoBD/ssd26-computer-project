import json
import uuid
import types
import enum
import requests
import os
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
from django.conf import settings

STEP_ROOT = os.getenv("STEP_ROOT", "/ca/certs/root_ca.crt")
STEP_INTERMEDIATE = os.getenv("STEP_INTERMEDIATE", "/ca/certs/intermediate_ca.crt")
logger = logging.getLogger(__name__)

# Using sha256 of a unique string → always the same salts → same PRF output on every device for the same credential
 # This guarantees stable KEK across sessions and synced devices (Apple/Google/1Password/Bitwarden all sync the PRF secret)
 # Using two salts + XOR = maximum compatibility (Apple sometimes only returns one, but XOR still works if both present)
PRF_SALT_FIRST = sha256(b"HealthSecure Project - PRF salt v1 - first").digest()
PRF_SALT_SECOND = sha256(b"HealthSecure Project - PRF salt v1 - second").digest()

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

def verify_certificate(certificate):
    import tempfile
    import os
    import subprocess

    cert = certificate.split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----\n"

    cert_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
    try:
        cert_file.write(cert.encode("utf-8"))
        cert_file.flush()
        cert_file.close()

        verify = subprocess.run(
            [
                "openssl",
                "verify",
                "-CAfile",
                STEP_ROOT,
                "-untrusted",
                STEP_INTERMEDIATE,
                cert_file.name,
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        if "OK" not in verify.stdout:
            return {"valid": False, "detail": verify.stderr}

        inspect = subprocess.run(
            [
                "openssl",
                "x509",
                "-in",
                cert_file.name,
                "-noout",
                "-subject",
                "-nameopt",
                "RFC2253",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        cn = None
        subject = inspect.stdout.strip()
        if "CN=" in subject:
            cn = subject.split("CN=")[-1].split(",")[0].strip()

        return {"valid": True, "cn": cn}
    except subprocess.CalledProcessError as exc:
        return {"valid": False, "detail": exc.stderr}
    finally:
        try:
            os.unlink(cert_file.name)
        except OSError:
            pass


@method_decorator(csrf_exempt, name="dispatch")
class StartRegistration(View):
    def post(self, request):
        data = json.loads(request.body)

        # -- ReCAPTCHA
        recaptcha_token = data.get("recaptcha_token")
        if not recaptcha_token:
            return JsonResponse({"error": "reCAPTCHA token required"}, status=400)


        verify_url = "https://www.google.com/recaptcha/api/siteverify"
        verify_data = {
            "secret": settings.RECAPTCHA_SECRET_KEY,
            "response": recaptcha_token,
            "remoteip": request.META.get("REMOTE_ADDR"),  # better scoring
        }
        verify_resp = requests.post(verify_url, data=verify_data)
        verify_json = verify_resp.json()

        if not verify_json.get("success") or verify_json.get("score", 0) < settings.RECAPTCHA_SCORE_THRESHOLD:
            return JsonResponse({"error": "reCAPTCHA verification failed - are you for real?"}, status=400)
        # --- --- ---


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
        # in verify_result["cn"] expected_cn is now email
        if user.type == User.Type.DOCTOR:
            certificate = data.get("certificate")
            if not certificate:
                return JsonResponse({"error": "Certificate required for doctor registration"}, status=400)
            verify_result = verify_certificate(certificate)
            if not verify_result.get("valid"):
                return JsonResponse({"error": "Invalid certificate", "detail": verify_result.get("detail")}, status=400)
            expected_cn = email
            if verify_result["cn"] != expected_cn:
                return JsonResponse({"error": "Certificate name mismatch"}, status=400)
            user.certificate = certificate
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
            "residentKey": "preferred",
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
        if not WebAuthnCredential.objects.filter(user=user, is_primary=True).exists():
            credential.is_primary = True
            credential.save()


        user.is_active = True
        user.save()
        login(request, user)
        # Mark which credential was used for this session
        request.session['used_credential_id'] = websafe_encode(credential.credential_id)
        request.session['device_role'] = 'primary' if credential.is_primary else 'secondary'


        del request.session["reg_state"]
        del request.session["reg_user_id"]
        del request.session["reg_device_name"]

        # New: Handle encrypted private key if provided (from frontend)
        encrypted_priv = response.get('encrypted_priv')  # Parse from JSON body
        iv_b64 = response.get('iv_b64')
        if user.type == User.Type.DOCTOR and encrypted_priv and iv_b64:
            user.encrypted_private_key = encrypted_priv
            user.private_key_iv = iv_b64
            user.save()

        # Handle encrypted X25519 private key
        encrypted_xpriv = response.get('encrypted_xpriv')
        xiv_b64 = response.get('xiv_b64')
        if encrypted_xpriv and xiv_b64:
            user.encrypted_encryption_private = urlsafe_b64decode(encrypted_xpriv + '==')  # BinaryField expects bytes
            user.xpriv_iv = xiv_b64
            user.save()

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
            request.session['device_role'] = 'primary' if credential.is_primary else 'secondary'
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
        if not is_primary_device(request):
            return JsonResponse({"error": "Primary device required"}, status=403)

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
        if not primary_cred:
            return JsonResponse({"error": "No primary credential found"}, status=400)

        primary_id = primary_cred.credential_id
        if isinstance(primary_id, memoryview):
            primary_id = primary_id.tobytes()

        if credential_id != primary_id:
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

@method_decorator(csrf_exempt, name="dispatch")
class StartDeleteCredentialApproval(View):
    def post(self, request):
        if not request.user.is_authenticated:
            return JsonResponse({"error": "Authentication required"}, status=401)

        if not is_primary_device(request):
            return JsonResponse({"error": "Primary device required"}, status=403)

        data = json.loads(request.body or "{}")
        target_cred_id = data.get("target_cred_id")
        if not target_cred_id:
            return JsonResponse({"error": "target_cred_id required"}, status=400)

        # Target must exist + belong to user + must be secondary
        try:
            target_bin = websafe_decode(target_cred_id)
            target = WebAuthnCredential.objects.get(user=request.user, credential_id=target_bin)
        except WebAuthnCredential.DoesNotExist:
            return JsonResponse({"error": "Credential not found"}, status=404)

        if target.is_primary:
            return JsonResponse({"error": "Cannot delete primary device"}, status=403)

        # Authenticate using PRIMARY credential only
        primary_cred = WebAuthnCredential.objects.filter(user=request.user, is_primary=True).first()
        if not primary_cred:
            return JsonResponse({"error": "No primary credential found"}, status=400)

        options, state = server.authenticate_begin(
            credentials=[primary_cred.get_credential_data()],
            user_verification="required",
            extensions={"prf": {"eval": {"first": PRF_SALT_FIRST, "second": PRF_SALT_SECOND}}},
        )

        pk_options = dict(options.public_key)
        pk_options["allowCredentials"] = [{
            "type": "public-key",
            "id": websafe_encode(primary_cred.credential_id),
            "transports": primary_cred.transports,
        }]

        request.session["del_cred_approval_state"] = state
        request.session["del_target_cred_id"] = target_cred_id

        return JsonResponse(to_serializable(pk_options))


@method_decorator(csrf_exempt, name="dispatch")
class FinishDeleteCredentialApproval(View):
    def post(self, request):
        if not request.user.is_authenticated:
            return JsonResponse({"error": "Authentication required"}, status=401)

        if not is_primary_device(request):
            return JsonResponse({"error": "Primary device required"}, status=403)

        state = request.session.get("del_cred_approval_state")
        target_cred_id = request.session.get("del_target_cred_id")

        if not state or not target_cred_id:
            return JsonResponse({"error": "No delete approval in progress"}, status=400)

        response = json.loads(request.body)
        credential_id = websafe_decode(response["rawId"])

        primary_cred = WebAuthnCredential.objects.filter(user=request.user, is_primary=True).first()
        if not primary_cred:
            return JsonResponse({"error": "No primary credential found"}, status=400)

        primary_id = primary_cred.credential_id
        if isinstance(primary_id, memoryview):
            primary_id = primary_id.tobytes()

        # The assertion MUST be from primary credential
        if credential_id != primary_id:
            return JsonResponse({"error": "Not primary credential"}, status=403)

        client_data_json = websafe_decode(response["response"]["clientDataJSON"])
        authenticator_data = websafe_decode(response["response"]["authenticatorData"])
        signature = websafe_decode(response["response"]["signature"])

        client_data = CollectedClientData(client_data_json)
        authenticator_data_obj = AuthenticatorData(authenticator_data)

        server.authenticate_complete(
            state,
            [primary_cred.get_credential_data()],
            credential_id,
            client_data,
            authenticator_data_obj,
            signature,
        )

        if not authenticator_data_obj.is_user_verified:
            return JsonResponse({"error": "User verification required"}, status=400)

        # signCount anti-clone (même logique que add approval)
        current_counter = authenticator_data_obj.counter
        if primary_cred.supports_sign_count and current_counter <= primary_cred.sign_count:
            logger.warning(f"Possible clone during delete approval for user {request.user.id}")
            return JsonResponse({"error": "Possible cloned authenticator detected"}, status=400)

        if current_counter > primary_cred.sign_count and not primary_cred.supports_sign_count:
            primary_cred.supports_sign_count = True

        primary_cred.sign_count = current_counter
        primary_cred.save()

        # Delete target credential
        try:
            target_bin = websafe_decode(target_cred_id)
            target = WebAuthnCredential.objects.get(user=request.user, credential_id=target_bin)
        except WebAuthnCredential.DoesNotExist:
            # Already deleted -> ok
            target = None

        if target and target.is_primary:
            return JsonResponse({"error": "Cannot delete primary device"}, status=403)

        if target:
            deleted_name = target.name
            target.delete()
        else:
            deleted_name = "Unknown"

        # Log (optionnel mais utile)
        AuthenticationLog.objects.create(
            user=request.user,
            ip_address=request.META.get("REMOTE_ADDR"),
            device_name=deleted_name,
            success=True,
            metadata={"privileges": "delete_device"},
        )

        # cleanup session
        request.session.pop("del_cred_approval_state", None)
        request.session.pop("del_target_cred_id", None)

        return JsonResponse({"status": "OK"})



@method_decorator(csrf_exempt, name='dispatch')
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
        request.session['device_role'] = 'secondary'

        # Log
        AuthenticationLog.objects.create(
            user=user,
            ip_address=request.META.get('REMOTE_ADDR'),
            device_name=credential.name,
            success=True,
            metadata={'privileges': 'add_device'}
        )

        return JsonResponse({"status": "OK", "prf_enabled": prf_enabled})


@method_decorator(csrf_exempt, name="dispatch")
@method_decorator(login_required, name="dispatch")
class EncryptDoctorPrivkey(View):
    def post(self, request):
        if request.user.type != User.Type.DOCTOR:
            return JsonResponse({"error": "Not doctor"}, status=403)
        data = json.loads(request.body)
        request.user.encrypted_doctor_privkey = data["encrypted"]
        request.user.privkey_iv = data["iv"]
        request.user.save()

        # Log for monitoring
        AuthenticationLog.objects.create(
            user=request.user,
            ip_address=request.META.get('REMOTE_ADDR'),
            success=True,
            metadata={'privileges': 'encrypt_privkey', 'request_size': len(request.body)}
        )

        return JsonResponse({"status": "OK"})

@method_decorator(csrf_exempt, name="dispatch")
@method_decorator(login_required, name="dispatch")
class GetEncryptedPrivkey(View):
    def get(self, request):
        if request.user.type != User.Type.DOCTOR:
            return JsonResponse({"error": "Not doctor"}, status=403)
        if not request.user.encrypted_doctor_privkey:
            return JsonResponse({"error": "No key stored"}, status=404)

        # Log fetch for anomaly detection
        AuthenticationLog.objects.create(
            user=request.user,
            ip_address=request.META.get('REMOTE_ADDR'),
            success=True,
            metadata={'privileges': 'fetch_privkey'}
        )

        return JsonResponse({
            "encrypted": request.user.encrypted_doctor_privkey,
            "iv": request.user.privkey_iv
        })


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
            if not WebAuthnCredential.objects.filter(user=user, is_primary=True).exists():
                return JsonResponse({"error": "Primary device required"}, status=403)

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

@method_decorator(csrf_exempt, name="dispatch")
class DeleteCredential(View):
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
        response = JsonResponse({"status": "OK"})
        if request.user.is_authenticated:
            logout(request)
            request.session.flush()
        else:
            request.session.flush()
        response.delete_cookie('sessionid')
        response.delete_cookie('csrftoken')
        return response


def is_primary_device(request):
    if not request.user.is_authenticated:
        return False

    cid = request.session.get('used_credential_id')
    if not cid:
        return False

    try:
        WebAuthnCredential.objects.get(
            credential_id=websafe_decode(cid),
            user=request.user,
            is_primary=True,
        )
        return True
    except WebAuthnCredential.DoesNotExist:
        return False


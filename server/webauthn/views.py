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

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidKey

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
            
from common.input_validation import (
    InputError, parse_json_body, require_email, require_str, optional_str,
    require_choice, require_pem_cert
)

@method_decorator(csrf_exempt, name="dispatch")
class StartRegistration(View):
    def post(self, request):
        import re

        # ---- helpers (local, pour rester 100% copier-coller) ----
        EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

        def bad(msg, status=400):
            return JsonResponse({"error": msg}, status=status)

        def clean_str(v, field, *, max_len, lower=False, allow_empty=False):
            if not isinstance(v, str):
                raise ValueError(f"{field} must be a string")
            s = v.strip()
            if lower:
                s = s.lower()
            # bloque caractères de contrôle
            if any(ord(c) < 32 for c in s):
                raise ValueError(f"{field} contains invalid characters")
            if not allow_empty and len(s) == 0:
                raise ValueError(f"{field} is required")
            if len(s) > max_len:
                raise ValueError(f"{field} is too long")
            return s

        def opt_str(data, key, *, max_len, default=""):
            if key not in data or data[key] is None:
                return default
            return clean_str(data[key], key, max_len=max_len, allow_empty=True)

        # ---- 1) JSON parse + limite taille ----
        raw = request.body or b""
        if len(raw) > 50_000:  # protège contre body énorme (ajuste si besoin)
            return bad("Request body too large", status=413)

        try:
            data = json.loads(raw)
        except Exception:
            return bad("Invalid JSON", status=400)

        if not isinstance(data, dict):
            return bad("JSON body must be an object", status=400)

        # ---- 2) ReCAPTCHA ----
        try:
            recaptcha_token = clean_str(data.get("recaptcha_token", ""), "recaptcha_token", max_len=4096)
        except ValueError as e:
            return bad(str(e), status=400)

        verify_url = "https://www.google.com/recaptcha/api/siteverify"
        verify_data = {
            "secret": settings.RECAPTCHA_SECRET_KEY,
            "response": recaptcha_token,
            "remoteip": request.META.get("REMOTE_ADDR"),
        }

        try:
            verify_resp = requests.post(verify_url, data=verify_data, timeout=6)
            verify_json = verify_resp.json()
        except Exception:
            return bad("reCAPTCHA verification error", status=400)

        if (not verify_json.get("success")) or (verify_json.get("score", 0) < settings.RECAPTCHA_SCORE_THRESHOLD):
            return bad("reCAPTCHA verification failed - are you for real?", status=400)

        # ---- 3) Validation / sanitization des inputs ----
        try:
            email = clean_str(data.get("email", ""), "email", max_len=254, lower=True)
            if not EMAIL_RE.match(email):
                return bad("Invalid email format", status=400)

            first_name = clean_str(data.get("first_name", ""), "first_name", max_len=50)
            last_name = clean_str(data.get("last_name", ""), "last_name", max_len=50)

            user_type = clean_str(data.get("type", ""), "type", max_len=16, lower=False)
            if user_type not in (User.Type.PATIENT, User.Type.DOCTOR, "patient", "doctor"):
                # supporte soit la string, soit l'enum (selon ton modèle)
                return bad("Invalid user type", status=400)

            # normalise en valeur attendue par ton modèle
            # (si User.Type.PATIENT est une string "patient", ça marche pareil)
            if user_type == "patient":
                user_type = User.Type.PATIENT
            elif user_type == "doctor":
                user_type = User.Type.DOCTOR

            date_of_birth = opt_str(data, "date_of_birth", max_len=32, default=None)
            medical_organization = opt_str(data, "medical_organization", max_len=80, default="")

            device_name = opt_str(data, "device_name", max_len=40, default="")

        except ValueError as e:
            return bad(str(e), status=400)

        # ---- 4) Vérifs DB / cert doctor (avant création user) ----
        if User.objects.filter(email=email).exists():
            return bad("Email already taken", status=400)

        certificate = None
        if user_type == User.Type.DOCTOR:
            cert_raw = data.get("certificate", "")
            if not isinstance(cert_raw, str) or len(cert_raw.strip()) == 0:
                return bad("Certificate required for doctor registration", status=400)
            if len(cert_raw) > 20_000:
                return bad("Certificate too large", status=413)
            if "BEGIN CERTIFICATE" not in cert_raw or "END CERTIFICATE" not in cert_raw:
                return bad("Invalid certificate PEM", status=400)

            verify_result = verify_certificate(cert_raw)
            if not verify_result.get("valid"):
                return JsonResponse(
                    {"error": "Invalid certificate", "detail": verify_result.get("detail")},
                    status=400
                )
            expected_cn = email
            if verify_result.get("cn") != expected_cn:
                return bad("Certificate name mismatch", status=400)

            certificate = cert_raw

        # ---- 5) Création user (comportement identique en happy path) ----
        user = User.objects.create_user(
            email=email,
            first_name=first_name,
            last_name=last_name,
            type=user_type,
            date_of_birth=date_of_birth,
            medical_organization=medical_organization,
        )
        user.is_active = False
        if certificate is not None:
            user.certificate = certificate
        user.save()

        if user.type == User.Type.PATIENT:
            PatientRecord.objects.create(patient=user)

        # ---- 6) WebAuthn register begin (identique) ----
        options, state = server.register_begin(
            user={
                "id": str(user.id).encode(),
                "name": user.email,
                "displayName": f"{user.first_name} {user.last_name}",
            },
            credentials=[],
            user_verification="required",
        )

        pk_options = dict(options.public_key)
        pk_options["authenticatorSelection"] = {
            "requireResidentKey": True,
            "residentKey": "preferred",
            "userVerification": "preferred",
        }
        pk_options["extensions"] = {"prf": {}}

        request.session["reg_state"] = state
        request.session["reg_user_id"] = str(user.id)
        request.session["reg_device_name"] = device_name

        return JsonResponse(to_serializable(pk_options))


@method_decorator(csrf_exempt, name="dispatch")
class FinishRegistration(View):
    def post(self, request):
        import binascii

        # ---- helpers (local) ----
        def bad(msg, status=400):
            return JsonResponse({"error": msg}, status=status)

        def ensure_dict(v, field):
            if not isinstance(v, dict):
                raise ValueError(f"{field} must be an object")
            return v

        def ensure_str(v, field, *, max_len, allow_empty=False):
            if not isinstance(v, str):
                raise ValueError(f"{field} must be a string")
            s = v.strip()
            if any(ord(c) < 32 for c in s):
                raise ValueError(f"{field} contains invalid characters")
            if not allow_empty and len(s) == 0:
                raise ValueError(f"{field} is required")
            if len(s) > max_len:
                raise ValueError(f"{field} is too long")
            return s

        def opt_str(d, key, *, max_len, default=None):
            if not isinstance(d, dict):
                raise ValueError("Invalid JSON object")
            if key not in d or d[key] is None:
                return default
            return ensure_str(d[key], key, max_len=max_len, allow_empty=True)

        def ensure_list_of_str(v, field, *, max_items=10, max_len=40):
            if v is None:
                return []
            if not isinstance(v, list):
                raise ValueError(f"{field} must be a list")
            if len(v) > max_items:
                raise ValueError(f"{field} too many items")
            out = []
            for i, item in enumerate(v):
                if not isinstance(item, str):
                    raise ValueError(f"{field}[{i}] must be a string")
                if len(item) > max_len:
                    raise ValueError(f"{field}[{i}] too long")
                out.append(item)
            return out

        def hex32(v, field):
            s = ensure_str(v, field, max_len=200)
            try:
                b = bytes.fromhex(s)
            except ValueError:
                raise ValueError(f"{field} is not valid hex")
            if len(b) != 32:
                raise ValueError(f"{field} must be 32 bytes")
            return b

        # base64url safe decode (accept no padding)
        def b64url_decode_limited(v, field, *, max_in=6000, max_out=4096):
            s = ensure_str(v, field, max_len=max_in)
            # normalize padding
            pad = "=" * ((4 - (len(s) % 4)) % 4)
            try:
                raw = urlsafe_b64decode((s + pad).encode("utf-8"))
            except (binascii.Error, ValueError):
                raise ValueError(f"{field} is not valid base64url")
            if len(raw) > max_out:
                raise ValueError(f"{field} decoded payload too large")
            return raw

        # ---- 0) session state ----
        state = request.session.get("reg_state")
        user_id = request.session.get("reg_user_id")
        if not state or not user_id:
            return bad("No registration in progress", status=400)

        # validate UUID in session
        try:
            user_uuid = uuid.UUID(str(user_id))
        except Exception:
            return bad("Invalid registration session", status=400)

        try:
            user = User.objects.get(id=user_uuid)
        except User.DoesNotExist:
            return bad("User not found", status=400)

        # ---- 1) JSON parse + size limit ----
        raw = request.body or b""
        if len(raw) > 250_000:
            return bad("Request body too large", status=413)

        try:
            response = json.loads(raw)
        except Exception:
            return bad("Invalid JSON", status=400)

        if not isinstance(response, dict):
            return bad("JSON body must be an object", status=400)

        try:
            # ---- 2) Validate minimal WebAuthn structure ----
            resp_obj = ensure_dict(response.get("response"), "response")
            clientDataJSON_b64 = ensure_str(resp_obj.get("clientDataJSON"), "response.clientDataJSON", max_len=5000)
            attObj_b64 = ensure_str(resp_obj.get("attestationObject"), "response.attestationObject", max_len=200_000)

            # (optionnels mais on limite quand même)
            transports = ensure_list_of_str(response.get("transports", []), "transports", max_items=12, max_len=40)

            cer = response.get("clientExtensionResults", {})
            if cer is not None and not isinstance(cer, dict):
                raise ValueError("clientExtensionResults must be an object")

            prf_enabled = bool((cer or {}).get("prf", {}).get("enabled", False))

            # device name en session: re-check
            dev_name = request.session.get("reg_device_name", "Unnamed Device")
            if not isinstance(dev_name, str):
                dev_name = "Unnamed Device"
            dev_name = dev_name.strip()
            if len(dev_name) == 0:
                dev_name = "Unnamed Device"
            if len(dev_name) > 40:
                dev_name = dev_name[:40]

        except ValueError as e:
            return bad(str(e), status=400)

        # ---- 3) WebAuthn register_complete (identique) ----
        try:
            client_data_json = websafe_decode(clientDataJSON_b64)
            attestation_object = websafe_decode(attObj_b64)

            client_data = CollectedClientData(client_data_json)
            att_obj = AttestationObject(attestation_object)

            auth_data = server.register_complete(state, client_data, att_obj)  # fido2==1.1.3

        except Exception as e:
            # si attestation invalide / mismatch challenge / etc.
            return bad(f"Registration failed: {str(e)}", status=400)

        # ---- 4) Save credential (identique) ----
        try:
            credential = WebAuthnCredential.objects.create(
                user=user,
                credential_id=auth_data.credential_data.credential_id,
                public_key=cbor2.dumps(auth_data.credential_data.public_key),
                name=dev_name,
                sign_count=auth_data.counter,
                transports=transports,
                prf_enabled=prf_enabled,
                aaguid=auth_data.credential_data.aaguid,
            )

            # Mark as primary if first credential
            if not WebAuthnCredential.objects.filter(user=user, is_primary=True).exists():
                credential.is_primary = True
                credential.save()

            user.is_active = True

            # ---- 5) Optional keys / cert / encrypted blobs (validated) ----
            # public_key (hex 32 bytes)
            if "public_key" in response:
                try:
                    public_key_bytes = hex32(response.get("public_key"), "public_key")
                    X25519PublicKey.from_public_bytes(public_key_bytes)
                    user.encryption_public_key = public_key_bytes
                    logger.info(f"Public key set for user {user.email} during registration")
                except ValueError as e:
                    logger.error(f"Invalid public key during registration for {user.email}: {str(e)}")
                    return bad("Invalid public key", status=400)
                except Exception as e:
                    logger.error(f"Invalid public key during registration for {user.email}: {str(e)}")
                    return bad("Invalid public key", status=400)

            # signing_public_key (hex 32 bytes)
            if "signing_public_key" in response:
                try:
                    signing_public_key_bytes = hex32(response.get("signing_public_key"), "signing_public_key")
                    Ed25519PublicKey.from_public_bytes(signing_public_key_bytes)
                    user.signing_public_key = signing_public_key_bytes
                    logger.info(f"Signing public key set for user {user.email} during registration")
                except ValueError as e:
                    logger.error(f"Invalid signing public key during registration for {user.email}: {str(e)}")
                    return bad("Invalid signing public key", status=400)
                except Exception as e:
                    logger.error(f"Invalid signing public key during registration for {user.email}: {str(e)}")
                    return bad("Invalid signing public key", status=400)

            # Save doctor's certificate if provided (optionnel)
            if user.type == User.Type.DOCTOR:
                cert = response.get("certificate")
                if cert is not None:
                    if not isinstance(cert, str):
                        return bad("Invalid certificate", status=400)
                    if len(cert) > 20_000:
                        return bad("Certificate too large", status=413)
                    if cert and ("BEGIN CERTIFICATE" not in cert or "END CERTIFICATE" not in cert):
                        return bad("Invalid certificate PEM", status=400)
                    if cert:
                        # selon ton modèle : certificate_pem ou certificate
                        if hasattr(user, "certificate_pem"):
                            user.certificate_pem = cert
                        else:
                            user.certificate = cert
                        logger.info(f"Certificate PEM saved for doctor {user.email}")

            # Encrypted private key (doctor) if provided (strings, size-limited)
            encrypted_priv = response.get("encrypted_priv")
            iv_b64 = response.get("iv_b64")
            if user.type == User.Type.DOCTOR and encrypted_priv and iv_b64:
                if not isinstance(encrypted_priv, str) or len(encrypted_priv) > 6000:
                    return bad("Invalid encrypted_priv", status=400)
                if not isinstance(iv_b64, str) or len(iv_b64) > 256:
                    return bad("Invalid iv_b64", status=400)
                user.encrypted_private_key = encrypted_priv
                user.private_key_iv = iv_b64

            # Encrypted X25519 private key (base64url -> bytes) if provided
            encrypted_xpriv = response.get("encrypted_xpriv")
            xiv_b64 = response.get("xiv_b64")
            if encrypted_xpriv and xiv_b64:
                if not isinstance(xiv_b64, str) or len(xiv_b64) > 256:
                    return bad("Invalid xiv_b64", status=400)

                # decode base64url into bytes (BinaryField expects bytes)
                try:
                    xpriv_bytes = b64url_decode_limited(encrypted_xpriv, "encrypted_xpriv", max_in=6000, max_out=4096)
                except ValueError as e:
                    return bad(str(e), status=400)

                user.encrypted_encryption_private = xpriv_bytes
                user.xpriv_iv = xiv_b64

            # save user + login
            user.save()
            login(request, user)

            # Mark which credential was used for this session
            request.session["used_credential_id"] = websafe_encode(credential.credential_id)
            request.session["device_role"] = "primary" if credential.is_primary else "secondary"

            # clear reg session
            for k in ("reg_state", "reg_user_id", "reg_device_name"):
                if k in request.session:
                    del request.session[k]

            return JsonResponse({"status": "OK", "prf_enabled": prf_enabled, "user_id": str(user.id)})

        except Exception as e:
            import traceback
            logger.error(traceback.format_exc())
            return JsonResponse({"error": f"Registration failed: {str(e)}"}, status=400)


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
            logger.warning(f"Possible clone detected for credential {credential.id} (counter {current_counter} <= {credential.sign_count}) from IP {request.META.get('REMOTE_ADDR')}")
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

@method_decorator(csrf_exempt, name='dispatch')
@method_decorator(login_required, name='dispatch')
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
class AuthStatus(View):
    def get(self, request):
        return JsonResponse({
            'authenticated': request.user.is_authenticated
        })

@method_decorator(csrf_exempt, name='dispatch')
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

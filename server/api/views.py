from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.utils import timezone
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives import hashes
from datetime import datetime
import os
import logging
import requests
from cryptography.exceptions import InvalidSignature

from accounts.models import User, PatientRecord, DoctorPatientLink, PendingRequest
from django.db.models import Q
import json
import logging
import base64
import binascii
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from common.input_validation import parse_metadata, InputError
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import hmac

# API handlers
#
# This module is the security boundary for the backend
# It enforces role checks (patient vs doctor), appointment constraints, and pending workflows
# Encrypted record payloads are treated as opaque blobs
# The server stores ciphertext + wrapped DEKs but does not decrypt medical data
#
# Most endpoints emit small JSON metadata logs for later anomaly detection

logger = logging.getLogger(__name__)

def forward_to_logger(request, view_name, outcome, metadata=None):
    """Forward log entry to logger service """
    try:
        log_entry = {
            'user_id': str(request.user.id) if request.user.is_authenticated else 'anonymous',
            'action': view_name,
            'outcome': outcome,
            'metadata': metadata or {},
            'timestamp': timezone.now().isoformat(),
            'ip': request.META.get('REMOTE_ADDR'),
            'user_agent': request.META.get('HTTP_USER_AGENT', ''),
        }
        
        # Optional: Sign with server key
        if hasattr(settings, 'SERVER_SIGN_PRIV'):
            msg = json.dumps(log_entry, sort_keys=True).encode('utf-8')
            sig = settings.SERVER_SIGN_PRIV.sign(msg)
            log_entry['server_signature'] = base64.b64encode(sig).decode('utf-8')
        
        # Send to logger
        response = requests.post(
            settings.LOGGER_URL + 'log',
            json=log_entry,
            cert=(settings.SERVER_CERT, settings.SERVER_KEY),
            verify=settings.CA_CHAIN,
            timeout=5
        )
        if response.status_code != 201:
            logger.warning(f"Logger forward failed: {response.text}")
    except Exception as e:
        logger.error(f"Logger forward error: {str(e)}")

# Helper to compute blinded HMAC index for names/org (use in registration/update)
# SECRET from settings.HMAC_SECRET (add to settings.py as bytes)
def compute_hmac(value: str) -> str:
    return hmac.new(settings.HMAC_SECRET, value.lower().encode('utf-8'), hashes.SHA256()).hexdigest()

# Returns the authenticated user's profile summary for the frontend
# Only ID/type; client decrypts encrypted_profile for name/DOB/org
# Logs a small access metadata record for monitoring
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_current_user(request):
    try:
        metadata = parse_metadata(request, request.user)
    except InputError as e:
        forward_to_logger(request, 'get_current_user', 'fail')
        return Response({'error': str(e)}, status=e.status)
    user = request.user
    data = {
        'id': str(user.id),
        'type': user.type,
    }
    forward_to_logger(request, 'get_current_user', 'success', metadata) 
    
    return Response(data)

# New: Fetch encrypted_profile for a user (self or appointed)
# For appointed: check link if not self
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_encrypted_profile(request, user_id=None):
    try:
        metadata = parse_metadata(request, request.user)
    except InputError as e:
        forward_to_logger(request, 'get_encrypted_profile', 'fail')
        return Response({'error': str(e)}, status=e.status)
    
    if user_id is None:
        target_user = request.user
    else:
        try:
            target_user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            forward_to_logger(request, 'get_encrypted_profile', 'fail', metadata)
            return Response({'error': 'User not found'}, status=404)
        
        # Permission check: self or appointed (doctor to patient or vice versa)
        is_appointed = DoctorPatientLink.objects.filter(
            (Q(doctor=request.user, patient=target_user) | Q(doctor=target_user, patient=request.user))
        ).exists()
        if request.user != target_user and not is_appointed:
            forward_to_logger(request, 'get_encrypted_profile', 'fail', metadata)
            return Response({'error': 'Not authorized'}, status=403)

    if target_user.encrypted_profile is None:
        forward_to_logger(request, 'get_encrypted_profile', 'fail', metadata)
        return Response({'error': 'No profile data'}, status=404)

    enc_b64 = base64.b64encode(target_user.encrypted_profile).decode('utf-8')
    
    forward_to_logger(request, 'get_encrypted_profile', 'success', metadata)
    
    return Response({'encrypted_sensitive': enc_b64})

# New: Batch fetch encrypted_profiles for list of IDs (with permission checks)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def batch_encrypted_profiles(request):
    try:
        metadata = parse_metadata(request, request.user)
    except InputError as e:
        forward_to_logger(request, 'batch_encrypted_profiles', 'fail')
        return Response({'error': str(e)}, status=e.status)
    
    ids = request.data.get('ids', [])
    if not isinstance(ids, list) or len(ids) > 50 or len(ids) == 0:
        forward_to_logger(request, 'batch_encrypted_profiles', 'fail', metadata)
        return Response({'error': 'Invalid IDs (max 50)'}, status=400)

    # Get appointed users (bidirectional)
    appointed_ids = set()
    if request.user.type == User.Type.PATIENT:
        appointed_ids = {str(link.doctor.id) for link in DoctorPatientLink.objects.filter(patient=request.user)}
    elif request.user.type == User.Type.DOCTOR:
        appointed_ids = {str(link.patient.id) for link in DoctorPatientLink.objects.filter(doctor=request.user)}

    data = {}
    for uid in ids:
        try:
            target_user = User.objects.get(id=uid)
            if str(request.user.id) == uid or uid in appointed_ids:
                enc_b64 = base64.b64encode(target_user.encrypted_profile).decode('utf-8') if target_user.encrypted_profile else None
                data[uid] = {'encrypted_sensitive': enc_b64}
            else:
                data[uid] = {'error': 'Not authorized'}
        except User.DoesNotExist:
            data[uid] = {'error': 'User not found'}

    forward_to_logger(request, 'batch_encrypted_profiles', 'success', metadata)
    
    return Response({'profiles': data})

@api_view(['GET'])
@permission_classes([IsAuthenticated])
# Patient-only endpoint to fetch their encrypted medical record
# Server returns ciphertext + encrypted DEKs map + record signature
# No decryption happens here, client is responsible for crypto
def get_my_record(request):
    try:
        metadata = parse_metadata(request, request.user)
    except InputError as e:
        forward_to_logger(request, 'get_my_record', 'fail')
        return Response({'error': str(e)}, status=e.status)
    
    if request.user.type != User.Type.PATIENT:
        forward_to_logger(request, 'get_my_record', 'fail', metadata)
        return Response({'error': 'Only patients have records'}, status=403)

    record = request.user.medical_record
    
    forward_to_logger(request, 'get_my_record', 'success', metadata)
    
    return Response({
        'encrypted_data': base64.b64encode(record.encrypted_data).decode('utf-8') if record.encrypted_data else None,
        'encrypted_deks': record.encrypted_deks,
        'signature': base64.b64encode(record.record_signature).decode('utf-8') if record.record_signature else None,
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
# Patient-only endpoint to replace their encrypted record payload
# Expects base64 ciphertext and signature generated client-side
# Treats the payload as opaque, stores it, logs the write event
def update_my_record(request):
    try:
        metadata = parse_metadata(request, request.user)
    except InputError as e:
        forward_to_logger(request, 'update_my_record', 'fail')
        return Response({'error': str(e)}, status=e.status)
    
    if request.user.type != User.Type.PATIENT:
        forward_to_logger(request, 'update_my_record', 'fail', metadata)
        return Response({'error': 'Only patients can update'}, status=403)

    data = request.data
    record = request.user.medical_record
    record.encrypted_data = base64.b64decode(data['encrypted_data'])
    record.encrypted_deks = data['encrypted_deks']
    record.record_signature = base64.b64decode(data['signature'])
    record.save()
    
    forward_to_logger(request, 'update_my_record', 'success', metadata)
    
    return Response({'status': 'OK'})

@api_view(['POST'])
@permission_classes([IsAuthenticated])
# Patient appoints a doctor and optionally uploads a DEK wrapped for that doctor
# Link is stored in DoctorPatientLink
# If encrypted_dek is provided, it is inserted into the record.encrypted_deks map under doctor_id
def appoint_doctor(request, doctor_id):
    try:
        metadata = parse_metadata(request, request.user)
    except InputError as e:
        forward_to_logger(request, 'appoint_doctor', 'fail')
        return Response({'error': str(e)}, status=e.status)
    
    if request.user.type != User.Type.PATIENT:
        forward_to_logger(request, 'appoint_doctor', 'fail', metadata)
        return Response({'error': 'Only patients appoint'}, status=403)

    encrypted_dek = request.data.get('encrypted_dek')

    try:
        doctor = User.objects.get(id=doctor_id, type=User.Type.DOCTOR)
    except User.DoesNotExist:
        forward_to_logger(request, 'appoint_doctor', 'fail', metadata)
        return Response({'error': 'Invalid doctor'}, status=404)

    DoctorPatientLink.objects.create(doctor=doctor, patient=request.user)

    if encrypted_dek:
        record = request.user.medical_record
        record.encrypted_deks[str(doctor_id)] = encrypted_dek
        record.save()
    
    forward_to_logger(request, 'appoint_doctor', 'success', metadata)
    
    return Response({'status': 'OK'})

@api_view(['GET'])
@permission_classes([IsAuthenticated])
# Doctor-only endpoint to read a patient's encrypted record
# Requires an existing DoctorPatientLink (appointment gate)
# Returns ciphertext plus the DEK entry wrapped for the requesting doctor
def get_patient_record(request, patient_id):
    try:
        metadata = parse_metadata(request, request.user)
    except InputError as e:
        forward_to_logger(request, 'get_patient_record', 'fail')
        return Response({'error': str(e)}, status=e.status)
    
    if request.user.type != User.Type.DOCTOR:
        forward_to_logger(request, 'get_patient_record', 'fail', metadata)
        return Response({'error': 'Only doctors access'}, status=403)

    try:
        link = DoctorPatientLink.objects.get(doctor=request.user, patient_id=patient_id)
    except DoctorPatientLink.DoesNotExist:
        forward_to_logger(request, 'get_patient_record', 'fail', metadata)
        return Response({'error': 'Not appointed'}, status=403)

    record = PatientRecord.objects.get(patient_id=patient_id)
    encrypted_dek = record.encrypted_deks.get(str(request.user.id))
    
    forward_to_logger(request, 'get_patient_record', 'success', metadata)
    
    return Response({
        'encrypted_data': base64.b64encode(record.encrypted_data).decode('utf-8') if record.encrypted_data else None,
        'encrypted_dek': encrypted_dek if encrypted_dek else None,
        'signature': base64.b64encode(record.record_signature).decode('utf-8') if record.record_signature else None,
    })


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
# Patient removes an appointed doctor
# Deletes the appointment link and revokes DEK access by removing the doctor entry from encrypted_deks
# Also revokes any previously approved appointment PendingRequest to keep state consistent
def remove_doctor(request, doctor_id):
    try:
        metadata = parse_metadata(request, request.user)
    except InputError as e:
        forward_to_logger(request, 'remove_doctor', 'fail')
        return Response({'error': str(e)}, status=e.status)
    
    if request.user.type != User.Type.PATIENT:
        forward_to_logger(request, 'remove_doctor', 'fail', metadata)
        return Response({'error': 'Only patients can remove doctors'}, status=403)

    try:
        doctor = User.objects.get(id=doctor_id, type=User.Type.DOCTOR)
        link = DoctorPatientLink.objects.get(doctor=doctor, patient=request.user)
        link.delete()  # Atomic removal

        # Revoke DEK access: remove from patient's record
        record = request.user.medical_record
        if str(doctor_id) in record.encrypted_deks:
            del record.encrypted_deks[str(doctor_id)]
            record.save()

        pending = PendingRequest.objects.filter(requester=doctor, target=request.user, type='appointment', status='approved').first()
        if pending:
            pending.status = 'revoked'
            pending.save()
        
        forward_to_logger(request, 'remove_doctor', 'success', metadata)
        
        return Response({'status': 'OK'})

    except (User.DoesNotExist, DoctorPatientLink.DoesNotExist):
        forward_to_logger(request, 'remove_doctor', 'fail', metadata)
        return Response({'error': 'Invalid doctor or not appointed'}, status=404)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
# Patient-only list of currently appointed doctors
# Used by the UI to display trusted doctors and manage revocation
def get_my_doctors(request):
    try:
        metadata = parse_metadata(request, request.user)
    except InputError as e:
        forward_to_logger(request, 'get_my_doctors', 'fail')
        return Response({'error': str(e)}, status=e.status)
    
    if request.user.type != User.Type.PATIENT:
        forward_to_logger(request, 'get_my_doctors', 'fail', metadata)
        return Response({'error': 'Only patients can view appointed doctors'}, status=403)

    links = DoctorPatientLink.objects.filter(patient=request.user)
    doctors = [
        {
            'id': str(link.doctor.id),  # UUID as string
        }
        for link in links
    ]
    
    forward_to_logger(request, 'get_my_doctors', 'success', metadata)
    
    return Response({'doctors': doctors})

@api_view(['GET'])
@permission_classes([IsAuthenticated])
# Doctor-only list of currently appointed patients
# Used by doctor portal to view records and send file requests
def get_my_patients(request):
    try:
        metadata = parse_metadata(request, request.user)
    except InputError as e:
        forward_to_logger(request, 'get_my_patients', 'fail')
        return Response({'error': str(e)}, status=e.status)
    
    if request.user.type != User.Type.DOCTOR:
        forward_to_logger(request, 'get_my_patients', 'fail', metadata)
        return Response({'error': 'Only doctors can view appointed patients'}, status=403)

    links = DoctorPatientLink.objects.filter(doctor=request.user)
    patients = [
        {
            'id': str(link.patient.id),
            'appointedDate': link.appointed_at.isoformat(),
        }
        for link in links
    ]
    
    forward_to_logger(request, 'get_my_patients', 'success', metadata)
    
    return Response({'patients': patients})

@api_view(['GET'])
@permission_classes([IsAuthenticated])
# Patient-only doctor search directory
# Returns all doctor IDs (small DB assumption); client fetches batch profiles and searches locally
def search_doctors(request):
    try:
        metadata = parse_metadata(request, request.user)
    except InputError as e:
        forward_to_logger(request, 'search_doctors', 'fail')
        return Response({'error': str(e)}, status=e.status)
    
    if request.user.type != User.Type.PATIENT:
        forward_to_logger(request, 'search_doctors', 'fail', metadata)
        return Response({'error': 'Only patients can search doctors'}, status=403)

    doctors = User.objects.filter(type=User.Type.DOCTOR)
    data = [
        {
            'id': str(d.id),
        } for d in doctors
    ]
    
    forward_to_logger(request, 'search_doctors', 'success', metadata)
    
    return Response({'doctors': data})

@api_view(['GET'])
@permission_classes([IsAuthenticated])
# Doctor-only patient search
# Used when requesting an appointment, does not return record data
def search_patients(request):
    try:
        metadata = parse_metadata(request, request.user)
    except InputError as e:
        forward_to_logger(request, 'search_patients', 'fail')
        return Response({'error': str(e)}, status=e.status)
    
    if request.user.type != User.Type.DOCTOR:
        forward_to_logger(request, 'search_patients', 'fail', metadata)
        return Response({'error': 'Only doctors can search patients'}, status=403)

    patients = User.objects.filter(type=User.Type.PATIENT)
    data = [
        {
            'id': str(p.id),
        } for p in patients
    ]
    
    forward_to_logger(request, 'search_patients', 'success', metadata)
    
    return Response({'patients': data})

# Stores user key material generated on the client
# Validates X25519 and Ed25519 public keys by parsing them
# Stores an encrypted private key blob (server never sees plaintext private keys)
# Notes: csrf_exempt is used because the client posts during setup flows, keep this scoped and audited
@csrf_exempt
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def update_user_keys(request):
    try:
        metadata = parse_metadata(request, request.user)
    except InputError as e:
        forward_to_logger(request, 'update_user_keys', 'fail')
        return Response({'error': str(e)}, status=e.status)
    
    user = request.user
    data = request.data

    if 'public_key' in data:
        try:
            public_key_bytes = bytes.fromhex(data['public_key'])
            X25519PublicKey.from_public_bytes(public_key_bytes)
            user.encryption_public_key = public_key_bytes
            logger.info(f"Public key updated for user {user.email} during registration")
        except (ValueError, binascii.Error):
            forward_to_logger(request, 'update_user_keys', 'fail', metadata)
            logger.error(f"Invalid public key during registration for {user.email}")
            return Response({'error': 'Invalid public key'}, status=400)

    if 'signing_public_key' in data:
        try:
            signing_public_key_bytes = bytes.fromhex(data['signing_public_key'])
            Ed25519PublicKey.from_public_bytes(signing_public_key_bytes)
            user.signing_public_key = signing_public_key_bytes
            logger.info(f"Signing public key updated for user {user.email}")
        except (ValueError, binascii.Error):
            forward_to_logger(request, 'update_user_keys', 'fail', metadata)
            logger.error(f"Invalid signing public key for user {user.email}")
            return Response({'error': 'Invalid signing public key'}, status=400)

    if 'encrypted_priv' in data:
        try:
            encrypted_priv_bytes = base64.b64decode(data['encrypted_priv'])
            if len(encrypted_priv_bytes) != 12 + 32 + 16:  # iv + ciphertext + tag for 32-byte priv
                raise ValueError
            user.encrypted_priv = encrypted_priv_bytes
            logger.info(f"Encrypted private key updated for user {user.email}")
        except ValueError:
            forward_to_logger(request, 'update_user_keys', 'fail', metadata)
            logger.error(f"Invalid encrypted private key for user {user.email}")
            return Response({'error': 'Invalid encrypted private key'}, status=400)

    if 'xiv_b64' in data:
        user.xpriv_iv = data['xiv_b64']
        logger.info(f"IV updated for user {user.email}")

    user.save()
    logger.info(f"User {user.email} saved after key update")
    
    forward_to_logger(request, 'update_user_keys', 'success', metadata)
    
    return Response({'status': 'OK'})

@api_view(['POST'])
@permission_classes([IsAuthenticated])
# Doctor requests an appointment with a patient
# Verifies the request signature using the public key extracted from the presented certificate
# Enforces a short timestamp window to reduce replay risk
# Stores the pending request for patient approval
def request_appointment(request):
    try:
        metadata = parse_metadata(request, request.user)
    except InputError as e:
        forward_to_logger(request, 'request_appointment', 'fail')
        return Response({'error': str(e)}, status=e.status)
    
    if request.user.type != User.Type.DOCTOR:
        forward_to_logger(request, 'request_appointment', 'fail', metadata)
        return Response({'error': 'Doctors only'}, status=403)
    data = request.data
    patient_id = data.get('patient_id')
    signature_b64 = data.get('signature')
    cert_pem = data.get('cert')  # Single doctor cert PEM
    timestamp = data.get('timestamp')
    if not timestamp:
        forward_to_logger(request, 'request_appointment', 'fail', metadata)
        return Response({'error': 'Missing timestamp'}, status=400)

    try:
        patient = User.objects.get(id=patient_id, type=User.Type.PATIENT)
        signature = base64.b64decode(signature_b64)

        # Load certificate and extract public key (no chain verification)
        cert = load_pem_x509_certificate(cert_pem.encode(), default_backend())
        cert_pub_key = cert.public_key()

        # Build exact same message as frontend, without spaces
        request_msg = json.dumps({
            'type': 'appointment_request',
            'patient_id': str(patient_id),
            'timestamp': timestamp
        }, separators=(',', ':')).encode()

        cert_pub_key.verify(
            signature,
            request_msg,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        now = timezone.now()
        req_time = datetime.fromisoformat(timestamp)
        if abs((now - req_time).total_seconds()) > 300:  # 5 minutes
            forward_to_logger(request, 'request_appointment', 'fail', metadata)
            return Response({'error': 'Request timestamp too old'}, status=400)

        if PendingRequest.objects.filter(requester=request.user, target=patient, type='appointment', status='pending').exists():
            forward_to_logger(request, 'request_appointment', 'fail', metadata)
            return Response({'error': 'Pending request already exists'}, status=400)

        # Store with cert for non-repudiation
        PendingRequest.objects.create(
            requester=request.user,
            target=patient,
            type='appointment',
            details={},
            signature=signature,
            cert_chain={'doctor': cert_pem}  # doctor cert
        )
        
        forward_to_logger(request, 'request_appointment', 'success', metadata)
        
        return Response({'status': 'OK'})
    except InvalidSignature:
        forward_to_logger(request, 'request_appointment', 'fail', metadata)
        return Response({'error': 'Invalid signature'}, status=400)
    except Exception as e:
        forward_to_logger(request, 'request_appointment', 'fail', metadata)
        logger.exception("Appointment request failed")
        return Response({'error': str(e)}, status=400)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
# Doctor-only view of requests created by the doctor
# Used for status tracking in the doctor portal
def get_pending_requests(request):
    try:
        metadata = parse_metadata(request, request.user)
    except InputError as e:
        forward_to_logger(request, 'get_pending_requests', 'fail')
        return Response({'error': str(e)}, status=e.status)
    
    if request.user.type != User.Type.DOCTOR:
        forward_to_logger(request, 'get_pending_requests', 'fail', metadata)
        return Response({'error': 'Doctors only'}, status=403)
    pending_requests = PendingRequest.objects.filter(requester=request.user)
    data = [{'id': str(r.id), 'type': r.type, 'status': r.status, 'patient_id': str(r.target.id), 'patient_email': r.target.email, 'timestamp': r.created_at.isoformat(), 'details': r.details} for r in pending_requests]
    
    forward_to_logger(request, 'get_pending_requests', 'success', metadata)
    
    return Response({'requests': data})

@api_view(['GET'])
@permission_classes([IsAuthenticated])
# Doctor-only endpoint to retrieve the local CA chain plus the user's stored doctor certificate
# This is used by the frontend to attach cert material to signed actions
def get_my_cert_chain(request):
    try:
        metadata = parse_metadata(request, request.user)
    except InputError as e:
        forward_to_logger(request, 'get_my_cert_chain', 'fail')
        return Response({'error': str(e)}, status=e.status)
    
    if request.user.type != User.Type.DOCTOR:
        forward_to_logger(request, 'get_my_cert_chain', 'fail', metadata)
        return Response({'error': 'Doctors only'}, status=403)
    try:
        
        with open(settings.STEP_ROOT, 'r') as f:
            root_pem = f.read()
        with open(settings.STEP_INTERMEDIATE, 'r') as f:
            intermediate_pem = f.read()
        doctor_pem = request.user.certificate
        if not doctor_pem:
            forward_to_logger(request, 'get_my_cert_chain', 'fail', metadata)
            return Response({'error': 'No certificate stored'}, status=400)
        
        forward_to_logger(request, 'get_my_cert_chain', 'success', metadata)
        
        return Response({
            'root_pem': root_pem,
            'intermediate_pem': intermediate_pem,
            'doctor_pem': doctor_pem,
        })
    except FileNotFoundError as e:
        forward_to_logger(request, 'get_my_cert_chain', 'fail', metadata)
        logger.error(f"FileNotFoundError: {str(e)}")
        return Response({'error': 'CA chain files missing'}, status=500)
    except Exception as e:
        forward_to_logger(request, 'get_my_cert_chain', 'fail', metadata)
        logger.error(f"Unexpected error: {str(e)}")
        return Response({'error': str(e)}, status=500)

# Convenience helper to extract a public key from a PEM certificate
def load_pub_from_cert(pem: str):
    cert = load_pem_x509_certificate(pem.encode(), default_backend())
    return cert.public_key()

# Verifies a root -> intermediate -> doctor certificate chain
# Checks signature linkage, issuer/subject continuity, and validity periods
def verify_cert_chain(chain: dict) -> bool:
    try:
        root_cert = load_pem_x509_certificate(chain['root'].encode(), default_backend())
        int_cert = load_pem_x509_certificate(chain['intermediate'].encode(), default_backend())
        doc_cert = load_pem_x509_certificate(chain['doctor'].encode(), default_backend())

        # Verify int issued by root
        root_pub = root_cert.public_key()
        verify_signature(root_pub, int_cert.signature, int_cert.tbs_certificate_bytes, int_cert.signature_hash_algorithm)

        # Verify doc issued by int
        int_pub = int_cert.public_key()
        verify_signature(int_pub, doc_cert.signature, doc_cert.tbs_certificate_bytes, doc_cert.signature_hash_algorithm)

        # Dates
        now = datetime.utcnow()
        if not (root_cert.not_valid_before_utc < now < root_cert.not_valid_after_utc):
            raise ValueError("Root expired")
        if not (int_cert.not_valid_before_utc < now < int_cert.not_valid_after_utc):
            raise ValueError("Intermediate expired")
        if not (doc_cert.not_valid_before_utc < now < doc_cert.not_valid_after_utc):
            raise ValueError("Doctor cert expired")

        # Issuer/subject match
        if int_cert.issuer != root_cert.subject or doc_cert.issuer != int_cert.subject:
            raise ValueError("Chain mismatch")

        return True
    except InvalidSignature:
        raise ValueError("Invalid chain signature")
    except Exception as e:
        raise ValueError(str(e))
# Verifies signatures for multiple key types (RSA, EC, Ed25519)
# Kept as a single helper to avoid duplicating verify logic in chain checks
def verify_signature(pub_key, signature: bytes, data: bytes, hash_alg=hashes.SHA256()):
    if isinstance(pub_key, RSAPublicKey):
        pub_key.verify(
            signature,
            data,
            padding.PSS(mgf=padding.MGF1(hash_alg), salt_length=padding.PSS.MAX_LENGTH),
            hash_alg
        )
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        pub_key.verify(signature, data, ec.ECDSA(hash_alg))
    elif isinstance(pub_key, Ed25519PublicKey):
        pub_key.verify(signature, data)
    else:
        raise ValueError("Unsupported public key type")

@api_view(['POST'])
@permission_classes([IsAuthenticated])
# Doctor creates a pending file change request for an appointed patient
# Appointment link is checked first
# Payload is signed and verified with the presented certificate public key before storing
def create_pending_request(request):
    try:
        metadata = parse_metadata(request, request.user)
    except InputError as e:
        forward_to_logger(request, 'create_pending_request', 'fail')
        return Response({'error': str(e)}, status=e.status)
    
    if request.user.type != User.Type.DOCTOR:
        forward_to_logger(request, 'create_pending_request', 'fail', metadata)
        return Response({'error': 'Doctors only'}, status=403)

    data = request.data
    patient_id = data.get('patient')
    type_ = data.get('type')
    details = data.get('details')
    signature_b64 = data.get('signature')
    cert_pem = data.get('cert')
    timestamp = data.get('timestamp', timezone.now().isoformat())

    try:
        patient = User.objects.get(id=patient_id, type=User.Type.PATIENT)
        if not DoctorPatientLink.objects.filter(doctor=request.user, patient=patient).exists():
            forward_to_logger(request, 'create_pending_request', 'fail', metadata)
            return Response({'error': 'Not appointed to this patient'}, status=403)

        signature = base64.b64decode(signature_b64)

        # Load certificate and extract public key
        cert = load_pem_x509_certificate(cert_pem.encode(), default_backend())
        cert_pub_key = cert.public_key()

        # Build exact same message as frontend, without spaces
        request_msg = json.dumps({
            'type': type_,
            'patient_id': str(patient_id),
            'details': details,
            'timestamp': timestamp
        }, separators=(',', ':')).encode()

        cert_pub_key.verify(
            signature,
            request_msg,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        # Store request
        PendingRequest.objects.create(
            requester=request.user,
            target=patient,
            type=type_,
            details=details,
            signature=signature,
            cert_chain={"root": "", "intermediate": "", "doctor": cert_pem},
        )
        
        forward_to_logger(request, 'create_pending_request', 'success', metadata)
        
        return Response({'status': 'OK'})

    except InvalidSignature:
        forward_to_logger(request, 'create_pending_request', 'fail', metadata)
        return Response({'error': 'Invalid signature'}, status=400)
    except Exception as e:
        forward_to_logger(request, 'create_pending_request', 'fail', metadata)
        logger.exception("File change request failed")
        return Response({'error': str(e)}, status=400)
    
@api_view(['GET'])
@permission_classes([IsAuthenticated])
# Returns a user's stored public keys for ECDH and signing
# Used to wrap DEKs and verify signatures client-side
def get_user_public_key(request, user_id):
    try:
        metadata = parse_metadata(request, request.user)
    except InputError as e:
        forward_to_logger(request, 'get_user_public_key', 'fail')
        return Response({'error': str(e)}, status=e.status)
    
    try:
        user = User.objects.get(id=user_id)
        response_data = {
            'public_key': user.encryption_public_key.hex() if user.encryption_public_key else None,
            'signing_public_key': user.signing_public_key.hex() if user.signing_public_key else None
        }
        
        forward_to_logger(request, 'get_user_public_key', 'success', metadata)
        
        return Response(response_data)
    except User.DoesNotExist:
        forward_to_logger(request, 'get_user_public_key', 'fail', metadata)
        return Response({'error': 'User not found'}, status=404)
    

@api_view(['GET'])
@permission_classes([IsAuthenticated])
# Lists pending requests addressed to the current user
# Patient uses this to approve or deny incoming requests
def get_pending_received(request):
    try:
        metadata = parse_metadata(request, request.user)
    except InputError as e:
        forward_to_logger(request, 'get_pending_received', 'fail')
        return Response({'error': str(e)}, status=e.status)
    
    requests = PendingRequest.objects.filter(target=request.user, status=PendingRequest.StatusChoices.PENDING)
    data = [{
        'id': str(r.id),
        'type': r.type,
        'requester': {'id': str(r.requester.id), 'email': r.requester.email},
        'details': r.details,
        'timestamp': r.created_at.isoformat(),
    } for r in requests]
    
    forward_to_logger(request, 'get_pending_received', 'success', metadata)
    
    return Response({'requests': data})

@api_view(['GET'])
@permission_classes([IsAuthenticated])
# Patient-only view of pending appointment requests
def get_pending_appointments(request):
    try:
        metadata = parse_metadata(request, request.user)
    except InputError as e:
        forward_to_logger(request, 'get_pending_appointments', 'fail')
        return Response({'error': str(e)}, status=e.status)
    
    if request.user.type != User.Type.PATIENT:
        forward_to_logger(request, 'get_pending_appointments', 'fail', metadata)
        return Response({'error': 'Patients only'}, status=403)

    requests = PendingRequest.objects.filter(target=request.user, type='appointment', status='pending')
    data = [{
        'id': str(r.id),
        'requester': {'id': str(r.requester.id)},
        'timestamp': r.created_at.isoformat(),
    } for r in requests]
    
    forward_to_logger(request, 'get_pending_appointments', 'success', metadata)
    
    return Response({'requests': data})

@api_view(['GET'])
@permission_classes([IsAuthenticated])
# Patient-only view of pending file requests from currently appointed doctors
def get_pending_file_requests(request):
    try:
        metadata = parse_metadata(request, request.user)
    except InputError as e:
        forward_to_logger(request, 'get_pending_file_requests', 'fail')
        return Response({'error': str(e)}, status=e.status)
    
    if request.user.type != User.Type.PATIENT:
        forward_to_logger(request, 'get_pending_file_requests', 'fail', metadata)
        return Response({'error': 'Patients only'}, status=403)

    appointed_doctors = [link.doctor.id for link in DoctorPatientLink.objects.filter(patient=request.user)]

    requests = PendingRequest.objects.filter(target=request.user, status='pending').exclude(type='appointment').filter(requester_id__in=appointed_doctors)
    data = [{
        'id': str(r.id),
        'type': r.type,
        'requester': {'id': str(r.requester.id), 'email': r.requester.email},
        'details': r.details,
        'timestamp': r.created_at.isoformat(),
    } for r in requests]
    
    forward_to_logger(request, 'get_pending_file_requests', 'success', metadata)
    
    return Response({'requests': data})

@api_view(['POST'])
@permission_classes([IsAuthenticated])
# Patient approves a pending request
# For appointments: stores the DEK wrapped for the doctor and ensures the appointment link exists
# For file requests: backend only updates status, client applies record changes after approval
def approve_pending(request, pk):
    try:
        metadata = parse_metadata(request, request.user)
    except InputError as e:
        forward_to_logger(request, 'approve_pending', 'fail')
        return Response({'error': str(e)}, status=e.status)
    
    if request.user.type != User.Type.PATIENT:
        forward_to_logger(request, 'approve_pending', 'fail', metadata)
        return Response({'error': 'Patients only'}, status=403)
    try:
        pending = PendingRequest.objects.get(id=pk, target=request.user, status=PendingRequest.StatusChoices.PENDING)
    except PendingRequest.DoesNotExist:
        forward_to_logger(request, 'approve_pending', 'fail', metadata)
        return Response({'error': 'Request not found'}, status=404)

    # Type-specific
    if pending.type == 'appointment':
        encrypted_dek = request.data.get('encrypted_dek')
        if not encrypted_dek:
            forward_to_logger(request, 'approve_pending', 'fail', metadata)
            return Response({'error': 'Missing encrypted_dek'}, status=400)
        record = request.user.medical_record
        record.encrypted_deks[str(pending.requester.id)] = encrypted_dek
        record.save()
        DoctorPatientLink.objects.get_or_create(doctor=pending.requester, patient=request.user)
    # For file types, client handles record update, here just status

    pending.status = PendingRequest.StatusChoices.APPROVED
    pending.save()
    
    forward_to_logger(request, 'approve_pending', 'success', metadata)
    
    return Response({'status': 'approved'})

@api_view(['POST'])
@permission_classes([IsAuthenticated])
# Patient denies a pending request, status becomes rejected
def deny_pending(request, pk):
    try:
        metadata = parse_metadata(request, request.user)
    except InputError as e:
        forward_to_logger(request, 'deny_pending', 'fail')
        return Response({'error': str(e)}, status=e.status)
    
    if request.user.type != User.Type.PATIENT:
        forward_to_logger(request, 'deny_pending', 'fail', metadata)
        return Response({'error': 'Patients only'}, status=403)
    try:
        pending = PendingRequest.objects.get(id=pk, target=request.user, status='pending')
    except PendingRequest.DoesNotExist:
        forward_to_logger(request, 'deny_pending', 'fail', metadata)
        return Response({'error': 'Request not found'}, status=404)
    pending.status = 'rejected'
    pending.save()
    
    forward_to_logger(request, 'deny_pending', 'success', metadata)
    
    return Response({'status': 'rejected'})

@api_view(['POST'])
@permission_classes([IsAuthenticated])
# Patient initializes the "self" DEK entry once
# Used during first-time setup so the record can be encrypted and later shared via wrapped DEKs
def init_dek(request):
    try:
        metadata = parse_metadata(request, request.user)
    except InputError as e:
        forward_to_logger(request, 'init_dek', 'fail')
        return Response({'error': str(e)}, status=e.status)
    
    if request.user.type != User.Type.PATIENT:
        forward_to_logger(request, 'init_dek', 'fail', metadata)
        return Response({'error': 'Patients only'}, status=403)

    encrypted_dek_self = request.data.get('encrypted_dek_self')
    if not encrypted_dek_self:
        forward_to_logger(request, 'init_dek', 'fail', metadata)
        return Response({'error': 'Missing encrypted_dek_self'}, status=400)

    try:
        record, created = PatientRecord.objects.get_or_create(patient=request.user)
    except Exception as e:
        forward_to_logger(request, 'init_dek', 'fail', metadata)
        logger.exception("Failed to get or create PatientRecord")
        return Response({'error': 'Record access failed'}, status=500)

    if "self" in record.encrypted_deks:
        forward_to_logger(request, 'init_dek', 'fail', metadata)
        return Response({'error': 'DEK already initialized'}, status=400)

    record.encrypted_deks["self"] = encrypted_dek_self
    record.save()
    
    forward_to_logger(request, 'init_dek', 'success', metadata)
    
    return Response({'status': 'DEK initialized'})

@api_view(['GET'])
def health(request):
    header = request.headers.get('X-Metadata', '{}')
    try:
        metadata = json.loads(base64.b64decode(header.split('|')[0]).decode('utf-8'))
    except:
        metadata = {}
    
    forward_to_logger(request, 'health', 'success', metadata)
    
    return Response({"status": "ok", "message": "Backend is running!"})

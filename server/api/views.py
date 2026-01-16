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


logger = logging.getLogger(__name__)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_current_user(request):
    user = request.user
    data = {
        'id': str(user.id),
        'type': user.type,
        'name': f"{user.first_name} {user.last_name}",
    }
    if user.type == User.Type.PATIENT:
        data['dob'] = user.date_of_birth.isoformat() if user.date_of_birth else None
    elif user.type == User.Type.DOCTOR:
        data['org'] = user.medical_organization
    metadata = {
        'time': timezone.now().isoformat(),
        'size': 0,
        'privileges': 'read_own_profile',
        'tree_depth': 1,
    }
    logger.info(json.dumps(metadata))
    return Response(data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_my_record(request):
    if request.user.type != User.Type.PATIENT:
        return Response({'error': 'Only patients have records'}, status=403)

    record = request.user.medical_record
    metadata = {
        'time': timezone.now().isoformat(),
        'size': len(record.encrypted_data) if record.encrypted_data else 0,
        'privileges': 'read_own_record',
        'tree_depth': 1,  # flat record
    }
    logger.info(json.dumps(metadata))  # anomaly detec ready

    return Response({
        'encrypted_data': base64.b64encode(record.encrypted_data).decode('utf-8') if record.encrypted_data else None,
        'encrypted_deks': record.encrypted_deks,
        'signature': base64.b64encode(record.record_signature).decode('utf-8') if record.record_signature else None,
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def update_my_record(request):
    if request.user.type != User.Type.PATIENT:
        return Response({'error': 'Only patients can update'}, status=403)

    data = request.data
    record = request.user.medical_record
    record.encrypted_data = base64.b64decode(data['encrypted_data'])
    record.encrypted_deks = data['encrypted_deks']
    record.record_signature = base64.b64decode(data['signature'])
    record.save()

    metadata = {
        'time': timezone.now().isoformat(),
        'size': len(record.encrypted_data),
        'privileges': 'write_own_record',
        'tree_depth': 1,
    }
    logger.info(json.dumps(metadata))

    return Response({'status': 'OK'})

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def appoint_doctor(request, doctor_id):
    if request.user.type != User.Type.PATIENT:
        return Response({'error': 'Only patients appoint'}, status=403)

    encrypted_dek = request.data.get('encrypted_dek')

    try:
        doctor = User.objects.get(id=doctor_id, type=User.Type.DOCTOR)
    except User.DoesNotExist:
        return Response({'error': 'Invalid doctor'}, status=404)

    DoctorPatientLink.objects.create(doctor=doctor, patient=request.user)

    if encrypted_dek:
        record = request.user.medical_record
        record.encrypted_deks[str(doctor_id)] = encrypted_dek
        record.save()

    metadata = {
        'time': timezone.now().isoformat(),
        'size': len(encrypted_dek) if encrypted_dek else 0,
        'privileges': 'appoint_doctor',
        'tree_depth': 2,  # record + appointment
    }
    logger.info(json.dumps(metadata))

    return Response({'status': 'OK'})

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_patient_record(request, patient_id):
  if request.user.type != User.Type.DOCTOR:
    return Response({'error': 'Only doctors access'}, status=403)

  try:
    link = DoctorPatientLink.objects.get(doctor=request.user, patient_id=patient_id)
  except DoctorPatientLink.DoesNotExist:
    return Response({'error': 'Not appointed'}, status=403)

  record = PatientRecord.objects.get(patient_id=patient_id)
  encrypted_dek = record.encrypted_deks.get(str(request.user.id))
  metadata = {
    'time': timezone.now().isoformat(),
    'size': len(record.encrypted_data) if record.encrypted_data else 0,
    'privileges': 'read_patient_record',
    'tree_depth': 2,
  }
  logger.info(json.dumps(metadata))

  return Response({
    'encrypted_data': base64.b64encode(record.encrypted_data).decode('utf-8') if record.encrypted_data else None,
    'encrypted_dek': encrypted_dek if encrypted_dek else None,
    'signature': base64.b64encode(record.record_signature).decode('utf-8') if record.record_signature else None,
    'patient': {
      'name': f"{record.patient.first_name} {record.patient.last_name}",
      'dob': record.patient.date_of_birth.isoformat() if record.patient.date_of_birth else None
    }
  })


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def remove_doctor(request, doctor_id):
    if request.user.type != User.Type.PATIENT:
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

        metadata = {
            'time': timezone.now().isoformat(),
            'size': 0,  # No data size for removal
            'privileges': 'remove_doctor',
            'tree_depth': 2,  # Consistent with appointment
        }
        logger.info(json.dumps(metadata))

        return Response({'status': 'OK'})

    except (User.DoesNotExist, DoctorPatientLink.DoesNotExist):
        return Response({'error': 'Invalid doctor or not appointed'}, status=404)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_my_doctors(request):
    if request.user.type != User.Type.PATIENT:
        return Response({'error': 'Only patients can view appointed doctors'}, status=403)

    links = DoctorPatientLink.objects.filter(patient=request.user)
    doctors = [
        {
            'id': str(link.doctor.id),  # UUID as string
            'name': f"{link.doctor.first_name} {link.doctor.last_name}",
            'org': link.doctor.medical_organization
        }
        for link in links
    ]

    metadata = {
        'time': timezone.now().isoformat(),
        'size': len(doctors),  # Number of doc
        'privileges': 'read_appointed_doctors',
        'tree_depth': 1,  # Flat list
    }
    logger.info(json.dumps(metadata))

    return Response({'doctors': doctors})

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_my_patients(request):
    if request.user.type != User.Type.DOCTOR:
        return Response({'error': 'Only doctors can view appointed patients'}, status=403)

    links = DoctorPatientLink.objects.filter(doctor=request.user)
    patients = [
        {
            'id': str(link.patient.id),
            'name': f"{link.patient.first_name} {link.patient.last_name}",
            'dob': link.patient.date_of_birth.isoformat() if link.patient.date_of_birth else None,
            'appointedDate': link.appointed_at.isoformat(),
        }
        for link in links
    ]

    metadata = {
        'time': timezone.now().isoformat(),
        'size': len(patients),
        'privileges': 'read_appointed_patients',
        'tree_depth': 1,
    }
    logger.info(json.dumps(metadata))

    return Response({'patients': patients})

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def search_doctors(request):
    if request.user.type != User.Type.PATIENT:
        return Response({'error': 'Only patients can search doctors'}, status=403)

    q = request.GET.get('q', '')
    doctors = User.objects.filter(type=User.Type.DOCTOR).filter(
        Q(first_name__icontains=q) | Q(last_name__icontains=q) | Q(medical_organization__icontains=q)
    )
    data = [
        {
            'id': str(d.id),
            'name': f"{d.first_name} {d.last_name}",
            'org': d.medical_organization
        } for d in doctors
    ]

    metadata = {
        'time': timezone.now().isoformat(),
        'size': len(data),
        'privileges': 'search_doctors',
        'tree_depth': 1,
    }
    logger.info(json.dumps(metadata))

    return Response({'doctors': data})

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def search_patients(request):
    if request.user.type != User.Type.DOCTOR:
        return Response({'error': 'Only doctors can search patients'}, status=403)

    q = request.GET.get('q', '')
    patients = User.objects.filter(type=User.Type.PATIENT).filter(
        Q(first_name__icontains=q) | Q(last_name__icontains=q)
    )
    data = [
        {
            'id': str(p.id),
            'name': f"{p.first_name} {p.last_name}",
            'dob': p.date_of_birth.isoformat() if p.date_of_birth else None,
        } for p in patients
    ]

    metadata = {
        'time': timezone.now().isoformat(),
        'size': len(data),
        'privileges': 'search_patients',
        'tree_depth': 1,
    }
    logger.info(json.dumps(metadata))

    return Response({'patients': data})

@csrf_exempt
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def update_user_keys(request):
    user = request.user
    data = request.data

    if 'public_key' in data:
        try:
            public_key_bytes = bytes.fromhex(data['public_key'])
            X25519PublicKey.from_public_bytes(public_key_bytes)
            user.encryption_public_key = public_key_bytes
            logger.info(f"Public key updated for user {user.email} during registration")
        except (ValueError, binascii.Error):
            logger.error(f"Invalid public key during registration for {user.email}")
            return Response({'error': 'Invalid public key'}, status=400)

    if 'signing_public_key' in data:
        try:
            signing_public_key_bytes = bytes.fromhex(data['signing_public_key'])
            Ed25519PublicKey.from_public_bytes(signing_public_key_bytes)
            user.signing_public_key = signing_public_key_bytes
            logger.info(f"Signing public key updated for user {user.email}")
        except (ValueError, binascii.Error):
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
            logger.error(f"Invalid encrypted private key for user {user.email}")
            return Response({'error': 'Invalid encrypted private key'}, status=400)

    if 'xiv_b64' in data:
        user.xpriv_iv = data['xiv_b64']
        logger.info(f"IV updated for user {user.email}")

    user.save()
    logger.info(f"User {user.email} saved after key update")

    metadata = {
        'time': timezone.now().isoformat(),
        'size': len(data.get('public_key', '')) + len(data.get('encrypted_priv', '')),
        'privileges': 'update_keys',
        'tree_depth': 1,
    }
    logger.info(json.dumps(metadata))

    return Response({'status': 'OK'})

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def request_appointment(request):
    if request.user.type != User.Type.DOCTOR:
        return Response({'error': 'Doctors only'}, status=403)
    data = request.data
    patient_id = data.get('patient_id')
    signature_b64 = data.get('signature')
    cert_pem = data.get('cert')  # Single doctor cert PEM
    timestamp = data.get('timestamp')
    if not timestamp:
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
            return Response({'error': 'Request timestamp too old'}, status=400)

        if PendingRequest.objects.filter(requester=request.user, target=patient, type='appointment', status='pending').exists():
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

        metadata = {
            'time': timezone.now().isoformat(),
            'size': len(signature),
            'privileges': 'request_appointment',
            'tree_depth': 2,
        }
        logger.info(json.dumps(metadata))

        return Response({'status': 'OK'})
    except InvalidSignature:
        return Response({'error': 'Invalid signature'}, status=400)
    except Exception as e:
        logger.exception("Appointment request failed")
        return Response({'error': str(e)}, status=400)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_pending_requests(request):
    if request.user.type != User.Type.DOCTOR:
        return Response({'error': 'Doctors only'}, status=403)
    requests = PendingRequest.objects.filter(requester=request.user)
    data = [{'id': str(r.id), 'type': r.type, 'status': r.status, 'patient_id': str(r.target.id), 'patient_name': f"{r.target.first_name} {r.target.last_name}", 'timestamp': r.created_at.isoformat(), 'details': r.details} for r in requests]
    return Response({'requests': data})

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_my_cert_chain(request):
    if request.user.type != User.Type.DOCTOR:
        return Response({'error': 'Doctors only'}, status=403)
    try:
        
        with open(settings.STEP_ROOT, 'r') as f:
            root_pem = f.read()
        with open(settings.STEP_INTERMEDIATE, 'r') as f:
            intermediate_pem = f.read()
        doctor_pem = request.user.certificate
        if not doctor_pem:
            return Response({'error': 'No certificate stored'}, status=400)
        return Response({
            'root_pem': root_pem,
            'intermediate_pem': intermediate_pem,
            'doctor_pem': doctor_pem,
        })
    except FileNotFoundError as e:
        logger.error(f"FileNotFoundError: {str(e)}")
        return Response({'error': 'CA chain files missing'}, status=500)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return Response({'error': str(e)}, status=500)

def load_pub_from_cert(pem: str):
    cert = load_pem_x509_certificate(pem.encode(), default_backend())
    return cert.public_key()

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
def create_pending_request(request):
    if request.user.type != User.Type.DOCTOR:
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

        metadata = {
            'time': timezone.now().isoformat(),
            'size': len(signature),
            'privileges': 'create_pending_file_request',
            'tree_depth': details.get('path', '').count('/') + 2 if isinstance(details, dict) else 2,
        }
        logger.info(json.dumps(metadata))

        return Response({'status': 'OK'})

    except InvalidSignature:
        return Response({'error': 'Invalid signature'}, status=400)
    except Exception as e:
        logger.exception("File change request failed")
        return Response({'error': str(e)}, status=400)
    
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_user_public_key(request, user_id):
    try:
        user = User.objects.get(id=user_id)
        response_data = {
            'public_key': user.encryption_public_key.hex() if user.encryption_public_key else None,
            'signing_public_key': user.signing_public_key.hex() if user.signing_public_key else None
        }
        return Response(response_data)
    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=404)
    

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_pending_received(request):
    requests = PendingRequest.objects.filter(target=request.user, status=PendingRequest.StatusChoices.PENDING)
    data = [{
        'id': str(r.id),
        'type': r.type,
        'requester': {'id': str(r.requester.id), 'name': f"{r.requester.first_name} {r.requester.last_name}"},
        'details': r.details,
        'timestamp': r.created_at.isoformat(),
    } for r in requests]
    metadata = {
        'time': timezone.now().isoformat(),
        'size': len(data),
        'privileges': 'get_pending_received',
        'tree_depth': 1,
    }
    logger.info(json.dumps(metadata))
    return Response({'requests': data})

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_pending_appointments(request):
    if request.user.type != User.Type.PATIENT:
        return Response({'error': 'Patients only'}, status=403)

    requests = PendingRequest.objects.filter(target=request.user, type='appointment', status='pending')
    data = [{
        'id': str(r.id),
        'requester': {'id': str(r.requester.id), 'name': f"{r.requester.first_name} {r.requester.last_name}"},
        'timestamp': r.created_at.isoformat(),
    } for r in requests]
    return Response({'requests': data})

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_pending_file_requests(request):
    if request.user.type != User.Type.PATIENT:
        return Response({'error': 'Patients only'}, status=403)

    appointed_doctors = [link.doctor.id for link in DoctorPatientLink.objects.filter(patient=request.user)]

    requests = PendingRequest.objects.filter(target=request.user, status='pending').exclude(type='appointment').filter(requester_id__in=appointed_doctors)
    data = [{
        'id': str(r.id),
        'type': r.type,
        'requester': {'id': str(r.requester.id), 'name': f"{r.requester.first_name} {r.requester.last_name}"},
        'details': r.details,
        'timestamp': r.created_at.isoformat(),
    } for r in requests]
    return Response({'requests': data})

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def approve_pending(request, pk):
    if request.user.type != User.Type.PATIENT:
        return Response({'error': 'Patients only'}, status=403)
    try:
        pending = PendingRequest.objects.get(id=pk, target=request.user, status=PendingRequest.StatusChoices.PENDING)
    except PendingRequest.DoesNotExist:
        return Response({'error': 'Request not found'}, status=404)

    # Type-specific
    if pending.type == 'appointment':
        encrypted_dek = request.data.get('encrypted_dek')
        if not encrypted_dek:
            return Response({'error': 'Missing encrypted_dek'}, status=400)
        record = request.user.medical_record
        record.encrypted_deks[str(pending.requester.id)] = encrypted_dek
        record.save()
        DoctorPatientLink.objects.get_or_create(doctor=pending.requester, patient=request.user)
    # For file types, client handles record update, here just status

    pending.status = PendingRequest.StatusChoices.APPROVED
    pending.save()

    metadata = {
        'time': timezone.now().isoformat(),
        'size': len(request.data) if request.data else 0,
        'privileges': f'approve_{pending.type}',
        'tree_depth': 2,
    }
    logger.info(json.dumps(metadata))

    return Response({'status': 'approved'})

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def deny_pending(request, pk):
    if request.user.type != User.Type.PATIENT:
        return Response({'error': 'Patients only'}, status=403)
    try:
        pending = PendingRequest.objects.get(id=pk, target=request.user, status='pending')
    except PendingRequest.DoesNotExist:
        return Response({'error': 'Request not found'}, status=404)
    pending.status = 'rejected'
    pending.save()
    metadata = {
        'time': timezone.now().isoformat(),
        'size': 0,
        'privileges': f'deny_{pending.type}',
        'tree_depth': 2,
    }
    logger.info(json.dumps(metadata))
    return Response({'status': 'rejected'})

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def init_dek(request):
    if request.user.type != User.Type.PATIENT:
        return Response({'error': 'Patients only'}, status=403)

    encrypted_dek_self = request.data.get('encrypted_dek_self')
    if not encrypted_dek_self:
        return Response({'error': 'Missing encrypted_dek_self'}, status=400)

    try:
        record, created = PatientRecord.objects.get_or_create(patient=request.user)
    except Exception as e:
        logger.exception("Failed to get or create PatientRecord")
        return Response({'error': 'Record access failed'}, status=500)

    if "self" in record.encrypted_deks:
        return Response({'error': 'DEK already initialized'}, status=400)

    record.encrypted_deks["self"] = encrypted_dek_self
    record.save()

    metadata = {
        'time': timezone.now().isoformat(),
        'size': len(encrypted_dek_self),
        'privileges': 'init_dek',
        'tree_depth': 1,
    }
    logger.info(json.dumps(metadata))

    return Response({'status': 'DEK initialized'})

@api_view(['GET'])
def health(request):
    return Response({"status": "ok", "message": "Backend is running!"})

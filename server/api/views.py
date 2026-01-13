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
from cryptography.hazmat.primitives import hashes
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


logger = logging.getLogger('metadata')

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

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_user_public_key(request, user_id):
    try:
        user = User.objects.get(id=user_id)
        if not user.encryption_public_key:
            return Response({'public_key': None})
        return Response({'public_key': user.encryption_public_key.hex()})
    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=404)

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
    cert_chain = data.get('cert_chain')

    try:
        patient = User.objects.get(id=patient_id, type=User.Type.PATIENT)
        signature = base64.b64decode(signature_b64)
        # Verif signature and chain
        doctor_pub = load_pub_from_cert(cert_chain['doctor'])
        request_msg = json.dumps({ 'type': 'appointment_request', 'patient_id': str(patient_id), 'timestamp': data.get('timestamp', timezone.now().isoformat()) }).encode()
        if isinstance(doctor_pub, RSAPublicKey):
            doctor_pub.verify(
                signature,
                request_msg,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        else:
            doctor_pub.verify(signature, request_msg)
        verify_cert_chain(cert_chain)

        PendingRequest.objects.create(
            requester=request.user,
            target=patient,
            type='appointment',
            details={},  # Additional
            signature=signature,
            cert_chain=cert_chain,
        )

        metadata = {
            'time': timezone.now().isoformat(),
            'size': len(signature),
            'privileges': 'request_appointment',
            'tree_depth': 2,
        }
        logger.info(json.dumps(metadata))

        return Response({'status': 'OK'})
    except Exception as e:
        return Response({'error': str(e)}, status=400)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_pending_requests(request):
    if request.user.type != User.Type.DOCTOR:
        return Response({'error': 'Doctors only'}, status=403)
    requests = PendingRequest.objects.filter(requester=request.user)
    data = [{'id': str(r.id), 'type': r.type, 'status': r.status, 'details': r.details, 'patient_name': f"{r.target.first_name} {r.target.last_name}"} for r in requests]
    return Response({'requests': data})

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_my_cert_chain(request):
    if request.user.type != User.Type.DOCTOR:
        return Response({'error': 'Doctors only'}, status=403)
    # Assume certs stored in model or file; return PEM strings
    return Response({
        'root_pem': '-----BEGIN CERTIFICATE-----...',
        'intermediate_pem': '-----BEGIN CERTIFICATE-----...',
        'doctor_pem': request.user.certificate or '-----BEGIN CERTIFICATE-----...',
    })

def load_pub_from_cert(pem: str):
    cert = load_pem_x509_certificate(pem.encode(), default_backend())
    return cert.public_key()

def verify_cert_chain(chain: dict) -> bool:
    try:
        root_pem = chain.get('root')
        intermediate_pem = chain.get('intermediate')
        doctor_pem = chain.get('doctor')

        if not all([root_pem, intermediate_pem, doctor_pem]):
            raise ValueError("Incomplete chain")

        root_cert = load_pem_x509_certificate(root_pem.encode(), default_backend())
        intermediate_cert = load_pem_x509_certificate(intermediate_pem.encode(), default_backend())
        doctor_cert = load_pem_x509_certificate(doctor_pem.encode(), default_backend())

        # Verify intermediate signed by root
        root_pub = root_cert.public_key()
        intermediate_cert.verify(
            intermediate_cert.signature,
            intermediate_cert.tbs_certificate_bytes,
            ec.ECDSA(intermediate_cert.signature_hash_algorithm)
        )

        # Verify doctor signed by intermediate
        intermediate_pub = intermediate_cert.public_key()
        doctor_cert.verify(
            doctor_cert.signature,
            doctor_cert.tbs_certificate_bytes,
            ec.ECDSA(doctor_cert.signature_hash_algorithm)
        )

        # Check validity dates
        now = timezone.now()
        if not (root_cert.not_valid_before < now < root_cert.not_valid_after):
            raise ValueError("Root cert invalid")
        if not (intermediate_cert.not_valid_before < now < intermediate_cert.not_valid_after):
            raise ValueError("Intermediate cert invalid")
        if not (doctor_cert.not_valid_before < now < doctor_cert.not_valid_after):
            raise ValueError("Doctor cert invalid")

        # Optional: Check subject/issuer matching, revocation, etc.
        # e.g., if doctor_cert.issuer != intermediate_cert.subject: raise ValueError

        return True
    except InvalidSignature:
        raise ValueError("Invalid signature in chain")
    except Exception as e:
        raise ValueError(f"Chain verification failed: {str(e)}")


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
    cert_chain = data.get('cert_chain')

    try:
        patient = User.objects.get(id=patient_id, type=User.Type.PATIENT)
        signature = base64.b64decode(signature_b64)
        # Verify sig and chain
        doctor_pub = load_pub_from_cert(cert_chain['doctor'])
        request_msg = json.dumps({ 'type': type_, 'patient_id': str(patient_id), 'details': details, 'timestamp': data.get('timestamp', timezone.now().isoformat()) }).encode()
        if isinstance(doctor_pub, RSAPublicKey):
            doctor_pub.verify(
                signature,
                request_msg,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        else:
            doctor_pub.verify(signature, request_msg)
        verify_cert_chain(cert_chain)

        PendingRequest.objects.create(
            requester=request.user,
            target=patient,
            type=type_,
            details=details,
            signature=signature,
            cert_chain=cert_chain,
        )

        metadata = {
            'time': timezone.now().isoformat(),
            'size': len(signature),
            'privileges': 'create_pending_request',
            'tree_depth': 2,
        }
        logger.info(json.dumps(metadata))

        return Response({'status': 'OK'})
    except Exception as e:
        return Response({'error': str(e)}, status=400)

    
@api_view(['GET'])
def health(request):
    return Response({"status": "ok", "message": "Backend is running!"})

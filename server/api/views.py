from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.utils import timezone
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from accounts.models import User, PatientRecord, DoctorPatientLink
import json
import logging

logger = logging.getLogger('metadata')

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
    logger.info(json.dumps(metadata))  # anomaly detection ready

    return Response({
        'encrypted_data': record.encrypted_data.hex() if record.encrypted_data else None,
        'encrypted_deks': record.encrypted_deks,
        'signature': record.record_signature.hex() if record.record_signature else None,
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def update_my_record(request):
    if request.user.type != User.Type.PATIENT:
        return Response({'error': 'Only patients can update'}, status=403)

    data = request.data
    record = request.user.medical_record
    record.encrypted_data = bytes.fromhex(data['encrypted_data'])
    record.encrypted_deks = data['encrypted_deks']
    record.record_signature = bytes.fromhex(data['signature'])
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
def appoint_doctor(request):
    if request.user.type != User.Type.PATIENT:
        return Response({'error': 'Only patients appoint'}, status=403)

    doctor_id = request.data['doctor_id']
    encrypted_dek = request.data['encrypted_dek']  # ECDH encrypted for doctor

    try:
        doctor = User.objects.get(id=doctor_id, type=User.Type.DOCTOR)
    except User.DoesNotExist:
        return Response({'error': 'Invalid doctor'}, status=404)

    DoctorPatientLink.objects.create(doctor=doctor, patient=request.user)

    record = request.user.medical_record
    record.encrypted_deks[str(doctor_id)] = encrypted_dek
    record.save()  # assume client re-signs full record

    metadata = {
        'time': timezone.now().isoformat(),
        'size': len(encrypted_dek),
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
    metadata = {
        'time': timezone.now().isoformat(),
        'size': len(record.encrypted_data),
        'privileges': 'read_patient_record',
        'tree_depth': 2,
    }
    logger.info(json.dumps(metadata))

    return Response({
        'encrypted_data': record.encrypted_data.hex(),
        'encrypted_dek': record.encrypted_deks.get(str(request.user.id)),
        'signature': record.record_signature.hex(),
    })

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_user_public_key(request, user_id):
    try:
        user = User.objects.get(id=user_id)
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
            'name': f"{link.doctor.first_name} {link.doctor.last_name}"
        }
        for link in links
    ]

    metadata = {
        'time': timezone.now().isoformat(),
        'size': len(doctors),  # Number of doctors
        'privileges': 'read_appointed_doctors',
        'tree_depth': 1,  # Flat list
    }
    logger.info(json.dumps(metadata))

    return Response({'doctors': doctors})

@api_view(['GET'])
def health(request):
    return Response({"status": "ok", "message": "Backend is running!"})


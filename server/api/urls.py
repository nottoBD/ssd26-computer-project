# API URL routing for the HealthSecure backend
#
# This file defines the public REST surface exposed by the server
# Endpoints are grouped by responsibility:
#  - appointment and access control
#  - PKI / certificate operations
#  - medical record access
#  - pending approval workflows
#
# Authorization and cryptographic checks are enforced in the views, not here
from django.urls import path
from .views import health, get_my_record, update_my_record, appoint_doctor, get_patient_record, get_user_public_key, remove_doctor, get_my_doctors, get_current_user, search_doctors, get_my_patients, update_user_keys, get_my_cert_chain, request_appointment, search_patients, get_pending_requests, get_pending_appointments,  approve_pending, deny_pending, get_pending_received, create_pending_request, init_dek, get_pending_file_requests, get_encrypted_profile
from .ca import ca_root, ca_sign, ca_verify

urlpatterns = [
    # Appointment management and access delegation
    # Controls which doctors can access which patient records
    path('appoint/<uuid:doctor_id>/', appoint_doctor),
    path('appoint/doctors/', get_my_doctors),
    path('appoint/patients/', get_my_patients),
    path('appoint/remove/<uuid:doctor_id>/', remove_doctor),
    path('appoint/request/', request_appointment),  # POST for doctor requests
    
    # PKI / Certificate Authority endpoints
    # Used to bootstrap trust for doctors and verify certificate chains
    path('ca/my_chain/', get_my_cert_chain),  # GET for doctor's cert chain 
    path('ca/root/', ca_root),
    path('ca/sign/', ca_sign),
    path('ca/verify/', ca_verify),
    
    # Doctor directory
    path('doctors/search/', search_doctors),

    path('health/', health),

    path('patients/search/', search_patients),  # GET for patient search

    # Pending workflows
    # Covers appointment approvals and file modification requests
    path('pending/my_requests/', get_pending_requests),  # GET for doctor's pendings
    path('pending/appointments/', get_pending_appointments),
    path('pending/<int:pk>/approve/', approve_pending),
    path('pending/received/', get_pending_received),  # GET for patient's received pendings
    path('pending/<int:pk>/deny/', deny_pending),
    path('pending/create/', create_pending_request),
    path('pending/file_requests/', get_pending_file_requests),

    path('record/my/', get_my_record),
    path('record/patient/<uuid:patient_id>/', get_patient_record),
    path('record/update/', update_my_record),
    path('record/init_dek/', init_dek),

    path('user/public_key/<uuid:user_id>', get_user_public_key),
    path('user/keys/update/', update_user_keys),
    path('user/me/', get_current_user),
    path('user/profile/encrypted/', get_encrypted_profile),
    path('user/profile/encrypted/<uuid:user_id>/', get_encrypted_profile),
]


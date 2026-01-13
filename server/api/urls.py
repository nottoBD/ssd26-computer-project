from django.urls import path
from .views import health, get_my_record, update_my_record, appoint_doctor, get_patient_record, get_user_public_key, remove_doctor, get_my_doctors, get_current_user, search_doctors, get_my_patients, update_user_keys, get_my_cert_chain, request_appointment, search_patients, get_pending_requests, get_pending_appointments,  approve_pending
from .ca import ca_root, ca_sign, ca_verify

urlpatterns = [
    path('appoint/<uuid:doctor_id>/', appoint_doctor),
    path('appoint/doctors/', get_my_doctors),
    path('appoint/patients/', get_my_patients),
    path('appoint/remove/<uuid:doctor_id>/', remove_doctor),
    path('appoint/request/', request_appointment),  # POST for doctor requests
    
    path('ca/my_chain/', get_my_cert_chain),  # GET for doctor's cert chain 
    path('ca/root/', ca_root),
    path('ca/sign/', ca_sign),
    path('ca/verify/', ca_verify),
    
    path('doctors/search/', search_doctors),

    path('health/', health),

    path('patients/search/', search_patients),  # GET for patient search

    path('pending/my_requests/', get_pending_requests),  # GET for doctor's pendings
    path('pending/appointments/', get_pending_appointments),
    path('pending/<uuid:pk>/approve/', approve_pending),

    path('record/my/', get_my_record),
    path('record/patient/<uuid:patient_id>/', get_patient_record),
    path('record/update/', update_my_record),

    path('user/public_key/<uuid:user_id>', get_user_public_key),
    path('user/keys/update/', update_user_keys),
    path('user/me/', get_current_user),
]


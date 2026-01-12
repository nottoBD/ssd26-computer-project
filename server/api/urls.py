from django.urls import path
from .views import health, get_my_record, update_my_record, appoint_doctor, get_patient_record, get_user_public_key, remove_doctor, get_my_doctors, get_current_user, search_doctors, get_my_patients, update_user_keys
from .ca import ca_root, ca_sign, ca_verify

urlpatterns = [
    path('appoint/<uuid:doctor_id>/', appoint_doctor),
    path('appoint/doctors/', get_my_doctors),
    path('appoint/patients/', get_my_patients),
    path('appoint/remove/<uuid:doctor_id>/', remove_doctor),
    
    path('ca/root/', ca_root),
    path('ca/sign/', ca_sign),
    path('ca/verify/', ca_verify),

    path('doctors/search/', search_doctors),

    path('health/', health),

    path('record/my/', get_my_record),
    path('record/patient/<uuid:patient_id>/', get_patient_record),
    path('record/update/', update_my_record),

    path('user/<uuid:user_id>/public_key/', get_user_public_key),
    path('user/keys/update/', update_user_keys),
    path('user/me/', get_current_user),
]


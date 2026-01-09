from django.urls import path
from .views import health, get_my_record, update_my_record, appoint_doctor, get_patient_record, get_user_public_key, remove_doctor, get_my_doctors
from .ca import ca_root, ca_sign, ca_verify

urlpatterns = [
    path('record/my/', get_my_record),
    path('record/update/', update_my_record),
    path('appoint/', appoint_doctor),
    path('record/patient/<uuid:patient_id>/', get_patient_record),
    path('user/<uuid:user_id>/public_key/', get_user_public_key),
    path('appoint/remove/<uuid:doctor_id>/', remove_doctor),
    path('appoint/doctors/', get_my_doctors),

    path('health/', health),
    path('ca/root/', ca_root),
    path('ca/sign/', ca_sign),
    path('ca/verify/', ca_verify),
]

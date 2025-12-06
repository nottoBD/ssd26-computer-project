from django.urls import path
from .views import StartRegistration, FinishRegistration

urlpatterns = [
    path("register/start/", StartRegistration.as_view(), name="webauthn_register_start"),
    path("register/finish/", FinishRegistration.as_view(), name="webauthn_register_finish"),
    path("login/start/", StartAuthentication.as_view(), name="webauthn_login_start"),
    path("login/finish/", FinishAuthentication.as_view(), name="webauthn_login_finish"),
]


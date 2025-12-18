from django.urls import path
from .views import (
    StartRegistration,
    FinishRegistration,
    StartAuthentication,
    FinishAuthentication,
    AuthStatus,
    LogoutView,

    StartAddCredentialApproval,
    FinishAddCredentialApproval,
    StartAddCredential,
    FinishAddCredential,
)

urlpatterns = [
    path("register/start/", StartRegistration.as_view(), name="webauthn_register_start"),
    path("register/finish/", FinishRegistration.as_view(), name="webauthn_register_finish"),
    path("login/start/", StartAuthentication.as_view(), name="webauthn_login_start"),
    path("login/finish/", FinishAuthentication.as_view(), name="webauthn_login_finish"),
    path("auth/status/", AuthStatus.as_view(), name="auth_status"),
    path("logout/", LogoutView.as_view(), name="logout"),

    path("credential/add/approve/start/", StartAddCredentialApproval.as_view(), name="webauthn_add_approve_start"),
    path("credential/add/approve/finish/", FinishAddCredentialApproval.as_view(), name="webauthn_add_approve_finish"),
    path("credential/add/start/", StartAddCredential.as_view(), name="webauthn_add_start"),
    path("credential/add/finish/", FinishAddCredential.as_view(), name="webauthn_add_finish"),
]


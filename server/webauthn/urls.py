from django.urls import path
from .views import (
    StartRegistration,
    FinishRegistration,
    StartAuthentication,
    FinishAuthentication,
    AuthStatus,
    LogoutView,
    UserCredentials,
    UserActivity,
    DeleteCredential,
    StartAddCredentialApproval,
    FinishAddCredentialApproval,
    FinishAddCredential,
    StartAddWithCode,
    StartDeleteCredentialApproval,
    FinishDeleteCredentialApproval,
    GetEncryptedPrivkey,
)

urlpatterns = [
    path("register/start/", StartRegistration.as_view(), name="webauthn_register_start"),
    path("register/finish/", FinishRegistration.as_view(), name="webauthn_register_finish"),
    path("login/start/", StartAuthentication.as_view(), name="webauthn_login_start"),
    path("login/finish/", FinishAuthentication.as_view(), name="webauthn_login_finish"),
    path("auth/status/", AuthStatus.as_view(), name="auth_status"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path('user/encrypted-priv/', GetEncryptedPrivkey.as_view()),

    path("credential/add/approve/start/", StartAddCredentialApproval.as_view(), name="webauthn_add_approve_start"),
    path("credential/add/approve/finish/", FinishAddCredentialApproval.as_view(), name="webauthn_add_approve_finish"),
    path("credential/add/finish/", FinishAddCredential.as_view(), name="webauthn_add_finish"),
    path("add/start/", StartAddWithCode.as_view(), name="webauthn_add_with_code_start"),
    path("user/credentials/", UserCredentials.as_view(), name="user_credentials"),
    path("user/activity/", UserActivity.as_view(), name="user_activity"),
    path("credential/<str:cred_id>/delete/", DeleteCredential.as_view(), name="delete_credential"),
    path("credential/delete/approve/start/", StartDeleteCredentialApproval.as_view(), name="webauthn_delete_approve_start"),
    path("credential/delete/approve/finish/", FinishDeleteCredentialApproval.as_view(), name="webauthn_delete_approve_finish"),
]


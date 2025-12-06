from django.db import models
from django.conf import settings
import base64

class WebAuthnCredential(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="webauthn_credentials",
    )
    credential_id = models.BinaryField(unique=True)  # raw bytes
    public_key = models.BinaryField()
    sign_count = models.PositiveBigIntegerField(default=0)
    transports = models.JSONField(default=list, blank=True)
    name = models.CharField(max_length=100, default="My device")
    prf_enabled = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)

    def credential_id_b64(self):
        return base64.b64encode(self.credential_id).decode()

    def __str__(self):
        return f"{self.user.email} – {self.name}"

    def get_credential_data(self):
        from fido2.webauthn import AttestedCredentialData
        return AttestedCredentialData(self.credential_id, self.public_key, self.sign_count)

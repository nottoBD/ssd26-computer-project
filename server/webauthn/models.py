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

    class Meta:
            verbose_name = "WebAuthn Credential"
            verbose_name_plural = "WebAuthn Credentials"

    def __str__(self):
        return f"{self.user.email} – {self.name} ({'PRF' if self.prf_enabled else 'no PRF'})"

    def get_credential_data(self):
        return AttestedCredentialData(
            self.credential_id,
            self.public_key,
            self.sign_count,
        )

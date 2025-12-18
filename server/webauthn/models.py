from django.db import models
from django.conf import settings
import base64
from fido2.webauthn import AttestedCredentialData
import cbor2

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

    # Handling primary/secondary, CDA approval, anomaly log detection (bc no sign_count)
    aaguid = models.BinaryField(null=True, blank=True)
    is_primary = models.BooleanField(default=False)
    supports_sign_count = models.BooleanField(default=False) # Detects if sign counter increments

    class Meta:
            verbose_name = "WebAuthn Credential"
            verbose_name_plural = "WebAuthn Credentials"

    def __str__(self):
        return f"{self.user.email} – {self.name} ({'PRF' if self.prf_enabled else 'no PRF'})"

    def get_credential_data(self):
        """
        Return a proper AttestedCredentialData object using the create() factory
        This is the only correct way when attestation="none" (aaguid is ignored by the lib anyway)
        We store the public key CBOR-encoded to keep it as compact bytes in BinaryField
        """
        import cbor2
        return AttestedCredentialData.create(
            b"\x00" * 16,
            self.credential_id,
            cbor2.loads(self.public_key),
        )

class AuthenticationLog(models.Model):
    user = models.ForeignKey('accounts.User', on_delete=models.CASCADE, null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    device_name = models.CharField(max_length=100, blank=True)
    success = models.BooleanField(default=False)
    metadata = models.JSONField(default=dict, blank=True)


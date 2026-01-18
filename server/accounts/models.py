import uuid
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils import timezone


class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_unusable_password()  # passwordless on purpose
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        user = self.create_user(email, **extra_fields)
        if password:
            user.set_password(password)
        user.save(using=self._db)
        return user

class User(AbstractBaseUser, PermissionsMixin):
    class Type(models.TextChoices):
        PATIENT = "patient", "Patient"
        DOCTOR = "doctor", "Doctor"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True)
    type = models.CharField(max_length=10, choices=Type.choices)

    # Encrypted profile (IV + ciphertext + tag for names, DOB/org)
    encrypted_profile = models.BinaryField(null=True, blank=True)

    # Blinded indexes for search (HMAC of lowercased values)
    name_hmac = models.CharField(max_length=64, null=True, blank=True, db_index=True)
    org_hmac = models.CharField(max_length=64, null=True, blank=True, db_index=True)  # Doctor-only
    dob_hmac = models.CharField(max_length=64, null=True, blank=True, db_index=True)  # Patient-only

    # Doctor-only
    certificate = models.TextField(blank=True, null=True)  # Store PEM cert for doctors
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)  # for admin access
    date_joined = models.DateTimeField(default=timezone.now)

# Encryption keys for E2EE (X25519)
#   # 32 bytes X25519 public key
    encryption_public_key = models.BinaryField(null=True, blank=True)
    signing_public_key = models.BinaryField(null=True, blank=True)  # 32 bytes Ed25519 public key derived from X25519
  # AES-KEK encrypted 32 bytes X25519 private key
    encrypted_encryption_private = models.BinaryField(null=True, blank=True)
    xpriv_iv = models.CharField(max_length=24, null=True, blank=True)  # Base64-encoded 96-bit IV for X25519

    # Multi device
    pending_add_code = models.CharField(max_length=128, blank=True, null=True)
    pending_add_expiry = models.DateTimeField(blank=True, null=True)

    # For PRF-encrypted signing private key (PEM) for doctors
    encrypted_private_key = models.TextField(null=True, blank=True)  # Base64-encoded AES-GCM encrypted PEM
    private_key_iv = models.CharField(max_length=24, null=True, blank=True)  # Base64-encoded 96-bit IV

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["type"]

    def __str__(self):
        return self.email


class PatientRecord(models.Model):
    patient = models.OneToOneField(
        User, on_delete=models.CASCADE, related_name="medical_record"
    )
    # AES-GCM encrypted record (JSON serialized)
    encrypted_data = models.BinaryField(null=True, blank=True)
  # {user_id: hex(ECDH encrypted DEK)}
    encrypted_deks = models.JSONField(default=dict)
  # Ed25519 signature of encrypted_data
    record_signature = models.BinaryField(null=True, blank=True)

    def __str__(self):
        return f"Record of {self.patient.email}"


class DoctorPatientLink(models.Model):
    doctor = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="appointed_patients"
    )
    patient = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="appointed_doctors"
    )
    appointed_at = models.DateTimeField(auto_now_add=True)
    encrypted_profile = models.BinaryField(null=True, blank=True)  # AES-GCM encrypted {name, dob} for doctor (IV + ciphertext + tag)

    class Meta:
        unique_together = ("doctor", "patient")


class PendingRequest(models.Model):
    class StatusChoices(models.TextChoices):
        PENDING = 'pending', 'Pending'
        APPROVED = 'approved', 'Approved'
        REJECTED = 'rejected', 'Rejected'

    requester = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_requests')
    target = models.ForeignKey(User, on_delete=models.CASCADE, related_name='received_requests')
    type = models.CharField(max_length=50)  # e.g., 'appointment', 'file_add_folder', etc.
    details = models.JSONField(default=dict)  # e.g., {path, name, encrypted_data, mime, encrypted_dek}
    signature = models.BinaryField(null=True)  # Ed25519 sig for non-repudiation
    cert_chain = models.JSONField(default=dict)  # {root, intermediate, doctor PEMs}
    status = models.CharField(max_length=20, choices=StatusChoices.choices, default=StatusChoices.PENDING)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.type} request from {self.requester} to {self.target}"

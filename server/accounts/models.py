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
        return self.create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    class Type(models.TextChoices):
        PATIENT = "patient", "Patient"
        DOCTOR = "doctor", "Doctor"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=150)
    last_name = models.CharField(max_length=150)
    type = models.CharField(max_length=10, choices=Type.choices)

    # Patient-only
    date_of_birth = models.DateField(null=True, blank=True)

    # Doctor-only
    medical_organization = models.CharField(max_length=255, blank=True)

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)  # for admin access
    date_joined = models.DateTimeField(default=timezone.now)

# Encryption keys for E2EE (X25519)
#   # 32 bytes X25519 public key
    encryption_public_key = models.BinaryField(null=True, blank=True)
  # AES-KEK encrypted 32 bytes X25519 private key
    encrypted_encryption_private = models.BinaryField(null=True, blank=True)

    # Multi device
    pending_add_code = models.CharField(max_length=128, blank=True, null=True)
    pending_add_expiry = models.DateTimeField(blank=True, null=True)
    
    # For PRF-encrypted signing private key (PEM) for doctors
    encrypted_private_key = models.TextField(null=True, blank=True)  # Base64-encoded AES-GCM encrypted PEM
    private_key_iv = models.CharField(max_length=24, null=True, blank=True)  # Base64-encoded 96-bit IV

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["first_name", "last_name", "type"]

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

    class Meta:
        unique_together = ("doctor", "patient")


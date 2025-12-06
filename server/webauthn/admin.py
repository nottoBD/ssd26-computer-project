from django.contrib import admin
from .models import WebAuthnCredential

@admin.register(WebAuthnCredential)
class WebAuthnCredentialAdmin(admin.ModelAdmin):
    list_display = ("user", "name", "prf_enabled", "created_at")
    list_filter = ("prf_enabled",)


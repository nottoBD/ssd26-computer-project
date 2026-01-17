from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.html import format_html
from django.utils.safestring import mark_safe
from django.db.models import Q
from django.utils import timezone
from .models import User, PatientRecord, DoctorPatientLink, PendingRequest


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    ordering = ('email',)  # Default sort for changelist

    list_display = (
        'email', 'first_name', 'last_name', 'type', 'is_active', 'date_joined',
        'account_status', 'device_count', 'last_login_attempt', 'suspicious_activity'
    )
    list_filter = ('type', 'is_active', 'is_staff', 'date_joined')
    search_fields = ('email', 'first_name', 'last_name')
    readonly_fields = (
        'id', 'date_joined', 'encryption_public_key', 'signing_public_key',
        'encrypted_encryption_private', 'xpriv_iv', 'encrypted_private_key',
        'private_key_iv', 'pending_add_code', 'pending_add_expiry',
        'account_status', 'device_count', 'last_login_attempt', 'suspicious_activity'
    )
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal info', {'fields': ('first_name', 'last_name', 'type', 'date_of_birth', 'medical_organization', 'certificate')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
        ('Encryption & Security', {'fields': ('encryption_public_key', 'signing_public_key', 'encrypted_encryption_private', 'xpriv_iv', 'encrypted_private_key', 'private_key_iv')}),
        ('Multi-device', {'fields': ('pending_add_code', 'pending_add_expiry')}),
        ('Analysis', {'fields': ('account_status', 'device_count', 'last_login_attempt', 'suspicious_activity')}),
    )
    actions = ['delete_selected', 'mark_as_suspicious', 'revoke_access']

    def account_status(self, obj):
        issues = []
        if obj.type == 'patient':
            if not obj.date_of_birth:
                issues.append("Missing date of birth")
        elif obj.type == 'doctor':
            if not obj.medical_organization:
                issues.append("Missing medical organization")
            if not obj.certificate:
                issues.append("Missing certificate")
        if not obj.encryption_public_key:
            issues.append("Missing encryption public key")
        if not obj.signing_public_key:
            issues.append("Missing signing public key")
        if issues:
            return format_html('<span style="color: red;">Incoherent: {}</span>', '; '.join(issues))
        return mark_safe('<span style="color: green;">OK</span>')
    account_status.short_description = "Account Status"

    def device_count(self, obj):
        from webauthn.models import WebAuthnCredential
        return WebAuthnCredential.objects.filter(user=obj).count()
    device_count.short_description = "Devices"

    def last_login_attempt(self, obj):
        from webauthn.models import AuthenticationLog
        last_log = AuthenticationLog.objects.filter(user=obj).order_by('-timestamp').first()
        if last_log:
            return f"{last_log.timestamp} ({'Success' if last_log.success else 'Failed'})"
        return "No logs"
    last_login_attempt.short_description = "Last Login Attempt"

    def suspicious_activity(self, obj):
        from webauthn.models import AuthenticationLog
        failed_attempts = AuthenticationLog.objects.filter(user=obj, success=False).count()
        if failed_attempts > 5:
            return format_html('<span style="color: red;">High failed attempts ({})</span>', failed_attempts)
        recent_logs = AuthenticationLog.objects.filter(user=obj).order_by('-timestamp')[:10]
        ip_changes = len(set(log.ip_address for log in recent_logs if log.ip_address))
        if ip_changes > 3:
            return format_html('<span style="color: orange;">Multiple IPs ({})</span>', ip_changes)
        return mark_safe('<span style="color: green;">None detected</span>')
    suspicious_activity.short_description = "Suspicious Activity"

    def mark_as_suspicious(self, request, queryset):
        queryset.update(is_active=False)
        self.message_user(request, "Selected accounts marked as suspicious and deactivated.")
    mark_as_suspicious.short_description = "Mark as suspicious (deactivate)"

    def revoke_access(self, request, queryset):
        for user in queryset:
            user.webauthn_credentials.all().delete()  # Revoke all devices
        self.message_user(request, "Access revoked for selected accounts (devices deleted).")
    revoke_access.short_description = "Revoke all device access"


@admin.register(PatientRecord)
class PatientRecordAdmin(admin.ModelAdmin):
    ordering = ('patient__email',)  # Default sort for changelist
    list_display = ('patient', 'has_encrypted_data', 'dek_count', 'has_signature')
    list_filter = ('patient__type',)
    search_fields = ('patient__email',)
    readonly_fields = ('encrypted_data', 'encrypted_deks', 'record_signature', 'has_encrypted_data', 'dek_count', 'has_signature')

    def has_encrypted_data(self, obj):
        return bool(obj.encrypted_data)
    has_encrypted_data.boolean = True
    has_encrypted_data.short_description = "Has Data"

    def dek_count(self, obj):
        return len(obj.encrypted_deks)
    dek_count.short_description = "Shared DEKs"

    def has_signature(self, obj):
        return bool(obj.record_signature)
    has_signature.boolean = True
    has_signature.short_description = "Signed"


@admin.register(DoctorPatientLink)
class DoctorPatientLinkAdmin(admin.ModelAdmin):
    ordering = ('-appointed_at',)  # Default sort for changelist
    list_display = ('doctor', 'patient', 'appointed_at')
    list_filter = ('appointed_at',)
    search_fields = ('doctor__email', 'patient__email')


@admin.register(PendingRequest)
class PendingRequestAdmin(admin.ModelAdmin):
    ordering = ('-created_at',)  # Default sort for changelist (newest first)
    list_display = ('requester', 'target', 'type', 'status', 'created_at', 'is_suspicious')
    list_filter = ('type', 'status', 'created_at')
    search_fields = ('requester__email', 'target__email')
    readonly_fields = ('details', 'signature', 'cert_chain', 'is_suspicious')

    def is_suspicious(self, obj):
        if obj.status == 'pending' and (timezone.now() - obj.created_at).days > 7:
            return mark_safe('<span style="color: red;">Stale pending request</span>')
        return mark_safe('<span style="color: green;">OK</span>')
    is_suspicious.short_description = "Suspicious?"

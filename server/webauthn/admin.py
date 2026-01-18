from django.contrib import admin
from django.utils.html import format_html
from django.utils.safestring import mark_safe
from .models import WebAuthnCredential, AuthenticationLog


class WebAuthnCredentialAdmin(admin.ModelAdmin):
    ordering = ('-created_at',)
    list_display = ('user', 'prf_enabled', 'is_primary', 'supports_sign_count', 'sign_count', 'created_at', 'credential_status')
    list_filter = ('prf_enabled', 'is_primary', 'supports_sign_count', 'created_at')
    search_fields = ('user__email', 'name')
    readonly_fields = ('credential_id', 'public_key', 'transports', 'aaguid', 'credential_status')

    def credential_status(self, obj):
        issues = []
        if not obj.supports_sign_count and obj.sign_count == 0:
            issues.append("No sign count support (potential cloning risk)")
        if issues:
            return format_html('<span style="color: orange;">Warning: {}</span>', '; '.join(issues))
        return mark_safe('<span style="color: green;">OK</span>')
    credential_status.short_description = "Credential Status"


class AuthenticationLogAdmin(admin.ModelAdmin):
    ordering = ('-timestamp',)
    list_display = ('user', 'timestamp', 'ip_address', 'device_name', 'success', 'anomaly_detected')
    list_filter = ('success', 'timestamp')
    search_fields = ('user__email', 'ip_address', 'device_name')
    readonly_fields = ('metadata', 'anomaly_detected')

    def anomaly_detected(self, obj):
        if not obj.success:
            return mark_safe('<span style="color: red;">Failed login</span>')
        if 'unusual' in obj.metadata.get('notes', ''):
            return mark_safe('<span style="color: orange;">Anomaly noted</span>')
        return mark_safe('<span style="color: green;">None</span>')
    anomaly_detected.short_description = "Anomaly"


admin.site.register(WebAuthnCredential, WebAuthnCredentialAdmin)
admin.site.register(AuthenticationLog, AuthenticationLogAdmin)

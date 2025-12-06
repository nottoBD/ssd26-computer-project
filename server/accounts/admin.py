from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, PatientRecord, DoctorPatientLink

@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = ("email", "first_name", "last_name", "type")
    list_filter = ("type",)
    fieldsets = (
        (None, {"fields": ("email", "password")}),
        ("Personal info", {"fields": ("first_name", "last_name", "type", "date_of_birth", "medical_organization")}),
        ("Permissions", {"fields": ("is_active", "is_staff", "is_superuser", "groups", "user_permissions")}),
    )
    add_fieldsets = (
        (None, {
            "classes": ("wide",),
            "fields": ("email", "first_name", "last_name", "type", "password1", "password2"),
        }),
    )
    search_fields = ("email",)
    ordering = ("email",)

admin.site.register(PatientRecord)
admin.site.register(DoctorPatientLink)


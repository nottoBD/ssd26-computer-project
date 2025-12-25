#!/usr/bin/env python3

from allauth.account.adapter import DefaultAccountAdapter
from allauth.account.signals import user_signed_up
from django.dispatch import receiver
from .models import PatientRecord, User
from api.ca import ca_verify

class CustomAccountAdapter(DefaultAccountAdapter):
    def is_open_for_signup(self, request):
        #TODO: Restrict signup CAPTCHA
        return True

    def save_user(self, request, user, form, commit=True):
        user = super().save_user(request, user, form, commit=False)
        user.type = form.cleaned_data.get("type")
        user.date_of_birth = form.cleaned_data.get("date_of_birth")
        user.medical_organization = form.cleaned_data.get("medical_organization", "")
        if commit:
            user.save()
            if user.type == User.Type.PATIENT:
                PatientRecord.objects.create(patient=user)
        # PKI check for doctors
        if user.type == User.Type.DOCTOR:
            cert_data = request.POST.get("cert")  # Assume client cert
            if not ca_verify(cert_data):  # CA verify
                raise ValueError("Invalid doctor certificate")
        return user

# Signal post-signup (start registration)
@receiver(user_signed_up)
def after_signup(sender, request, user, **kwargs):
    # registration flow
    pass

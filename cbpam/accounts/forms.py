from django import forms
from django.contrib.auth.forms import AuthenticationForm
from django.core.exceptions import ValidationError

from cbpam.mfa.services import verify_user_totp

from .models import User


class PAMOliveAuthenticationForm(AuthenticationForm):
    username = forms.CharField(
        label="Identifiant",
        widget=forms.TextInput(
            attrs={
                "class": "form-input",
                "placeholder": "Votre identifiant",
                "autocomplete": "username",
                "autocapitalize": "none",
                "spellcheck": "false",
                "autofocus": True,
            }
        ),
    )
    password = forms.CharField(
        label="Mot de passe",
        strip=False,
        widget=forms.PasswordInput(
            attrs={
                "class": "form-input form-input-password",
                "placeholder": "Votre mot de passe",
                "autocomplete": "current-password",
            }
        ),
    )
    otp_token = forms.CharField(
        label="Code MFA",
        required=False,
        widget=forms.TextInput(
            attrs={
                "class": "form-input",
                "placeholder": "000000 (si activé)",
                "autocomplete": "one-time-code",
                "inputmode": "numeric",
                "maxlength": 6,
            }
        ),
    )

    def clean(self):
        cleaned = super().clean()
        user = self.get_user()
        if user and user.mfa_devices.filter(kind="totp", confirmed=True).exists():
            if not verify_user_totp(user, cleaned.get("otp_token", "")):
                raise ValidationError("Le code MFA est requis ou invalide.", code="invalid_mfa")
        return cleaned


class ProfileForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ("display_name", "email", "first_name", "last_name")
        labels = {
            "display_name": "Nom affiché",
            "email": "Adresse e-mail",
            "first_name": "Prénom",
            "last_name": "Nom",
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs["class"] = "console-input"


class MFAConfirmForm(forms.Form):
    token = forms.CharField(
        label="Code à six chiffres",
        min_length=6,
        max_length=6,
        widget=forms.TextInput(
            attrs={
                "class": "console-input",
                "autocomplete": "one-time-code",
                "inputmode": "numeric",
            }
        ),
    )

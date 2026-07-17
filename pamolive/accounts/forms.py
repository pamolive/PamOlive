from django import forms
from django.contrib.auth.forms import AuthenticationForm
from django.core.exceptions import ValidationError

from pamolive.mfa.services import verify_user_mfa

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
                "placeholder": "TOTP ou code de récupération",
                "autocomplete": "one-time-code",
            }
        ),
    )

    def clean(self):
        cleaned = super().clean()
        user = self.get_user()
        if user and user.mfa_devices.filter(kind="totp", confirmed=True).exists():
            if not verify_user_mfa(user, cleaned.get("otp_token", "")):
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


class PreferencesForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ("preferred_theme", "preferred_language")
        labels = {
            "preferred_theme": "Theme",
            "preferred_language": "Language",
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


class MFASecurityForm(forms.Form):
    password = forms.CharField(
        label="Mot de passe actuel",
        widget=forms.PasswordInput(attrs={"class": "console-input"}),
    )
    token = forms.CharField(
        label="Code TOTP ou code de récupération",
        widget=forms.TextInput(
            attrs={"class": "console-input", "autocomplete": "one-time-code"}
        ),
    )

    def __init__(self, *args, user, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    def clean_password(self):
        password = self.cleaned_data["password"]
        if not self.user.check_password(password):
            raise forms.ValidationError("Le mot de passe actuel est incorrect.")
        return password

    def clean_token(self):
        token = self.cleaned_data["token"]
        if not verify_user_mfa(self.user, token):
            raise forms.ValidationError("Le code de sécurité est incorrect.")
        return token

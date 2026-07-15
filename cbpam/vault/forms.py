from django import forms

from .models import PersonalVaultGroup, PersonalVaultItem


class PersonalVaultItemForm(forms.Form):
    name = forms.CharField(label="Nom")
    item_type = forms.ChoiceField(label="Type", choices=PersonalVaultItem.ItemType.choices)
    application = forms.CharField(label="Application", required=False)
    website_url = forms.URLField(label="URL", required=False)
    username = forms.CharField(label="Identifiant", required=False)
    password = forms.CharField(
        label="Mot de passe",
        required=False,
        widget=forms.PasswordInput(render_value=True),
    )
    totp_secret = forms.CharField(label="Secret TOTP", required=False)
    card_holder = forms.CharField(label="Titulaire", required=False)
    card_number = forms.CharField(label="Numéro de carte", required=False)
    expiry = forms.CharField(label="Expiration", required=False)
    cvv = forms.CharField(
        label="CVV",
        required=False,
        widget=forms.PasswordInput(render_value=True),
    )
    notes = forms.CharField(label="Notes", required=False, widget=forms.Textarea(attrs={"rows": 3}))
    favorite = forms.BooleanField(label="Favori", required=False)
    group = forms.ModelChoiceField(
        label="Groupe",
        queryset=PersonalVaultGroup.objects.none(),
        required=False,
        empty_label="Sans groupe",
    )

    def __init__(self, *args, owner=None, **kwargs):
        super().__init__(*args, **kwargs)
        if owner is not None:
            self.fields["group"].queryset = owner.personal_vault_groups.all()
        for field in self.fields.values():
            field.widget.attrs["class"] = "console-input"

    def clean(self):
        cleaned = super().clean()
        item_type = cleaned.get("item_type")
        if item_type == PersonalVaultItem.ItemType.LOGIN and not cleaned.get("password"):
            self.add_error("password", "Un mot de passe est requis pour un identifiant.")
        if item_type == PersonalVaultItem.ItemType.TOTP and not cleaned.get("totp_secret"):
            self.add_error("totp_secret", "Le secret TOTP est requis.")
        if item_type == PersonalVaultItem.ItemType.CARD and not cleaned.get("card_number"):
            self.add_error("card_number", "Le numéro de carte est requis.")
        if item_type == PersonalVaultItem.ItemType.NOTE and not cleaned.get("notes"):
            self.add_error("notes", "Le contenu de la note est requis.")
        return cleaned

    def encrypted_payload_data(self):
        return {
            key: value
            for key, value in self.cleaned_data.items()
            if key not in {"name", "item_type", "favorite", "group"} and value
        }


class PersonalVaultGroupForm(forms.ModelForm):
    class Meta:
        model = PersonalVaultGroup
        fields = ("name",)
        labels = {"name": "Nom du groupe"}

    def __init__(self, *args, owner, **kwargs):
        self.owner = owner
        super().__init__(*args, **kwargs)
        self.fields["name"].widget.attrs.update(
            {"class": "console-input", "placeholder": "Ex. Travail, Maison, Finance"}
        )

    def clean_name(self):
        name = self.cleaned_data["name"].strip()
        if PersonalVaultGroup.objects.filter(owner=self.owner, name__iexact=name).exists():
            raise forms.ValidationError("Un groupe portant ce nom existe déjà.")
        return name

    def save(self, commit=True):
        group = super().save(commit=False)
        group.owner = self.owner
        if commit:
            group.save()
        return group

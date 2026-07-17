from django import forms

from pamolive.common.justification import (
    MAX_JUSTIFICATION_LENGTH,
    MIN_JUSTIFICATION_LENGTH,
    normalize_justification,
)


class PrivilegedActionJustificationForm(forms.Form):
    justification = forms.CharField(
        label="Business justification",
        min_length=MIN_JUSTIFICATION_LENGTH,
        max_length=MAX_JUSTIFICATION_LENGTH,
        strip=True,
        widget=forms.TextInput(
            attrs={
                "class": "justification-input",
                "placeholder": "Why is this privileged action necessary?",
                "autocomplete": "off",
            }
        ),
    )

    def clean_justification(self):
        return normalize_justification(self.cleaned_data["justification"])

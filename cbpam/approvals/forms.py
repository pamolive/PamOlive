from django import forms

from cbpam.policies.models import AccessPolicy
from cbpam.policies.services import policies_allowing, targets_for_policies

from .models import AccessRequest


class AccessRequestForm(forms.ModelForm):
    class Meta:
        model = AccessRequest
        fields = (
            "policy",
            "target",
            "reason",
            "ticket_reference",
            "requested_duration_minutes",
        )
        labels = {
            "policy": "Politique d’accès",
            "target": "Cible demandée",
            "reason": "Justification",
            "ticket_reference": "Référence de ticket",
            "requested_duration_minutes": "Durée souhaitée (minutes)",
        }
        widgets = {
            "reason": forms.Textarea(
                attrs={"rows": 4, "placeholder": "Décrivez précisément le besoin métier…"}
            )
        }

    def __init__(self, *args, user, source_ip=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = user
        self.allowed_policies = policies_allowing(
            user,
            AccessPolicy.Action.REQUEST_ACCESS,
            source_ip=source_ip,
        )
        self.fields["policy"].queryset = self.allowed_policies
        self.fields["target"].queryset = targets_for_policies(self.allowed_policies)
        for field in self.fields.values():
            field.widget.attrs["class"] = "console-input"

    def clean(self):
        cleaned = super().clean()
        policy = cleaned.get("policy")
        target = cleaned.get("target")
        duration = cleaned.get("requested_duration_minutes")
        if policy and policy not in self.allowed_policies:
            self.add_error("policy", "Cette politique ne vous est pas attribuée.")
        if policy and target:
            target_allowed = (
                policy.target_groups.filter(targets=target, enabled=True).exists()
                or policy.targets.filter(pk=target.pk, enabled=True).exists()
            )
            if not target_allowed:
                self.add_error("target", "Cette cible n’est pas couverte par la politique choisie.")
        if policy and duration and duration > policy.max_duration_minutes:
            self.add_error(
                "requested_duration_minutes",
                f"La durée maximale de cette politique est {policy.max_duration_minutes} minutes.",
            )
        if policy and policy.ticket_required and not cleaned.get("ticket_reference"):
            self.add_error(
                "ticket_reference",
                "Une référence de ticket est obligatoire pour cette politique.",
            )
        return cleaned

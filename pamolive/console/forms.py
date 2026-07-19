import ipaddress
from datetime import timedelta

from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.utils import timezone

from pamolive.accounts.models import PlatformSecurityPolicy, User
from pamolive.audit.models import SIEMIntegration
from pamolive.connectors.models import DirectoryGroupMapping, IdentitySource
from pamolive.connectors.services import (
    get_identity_source_configuration,
    set_identity_source_configuration,
    validate_identity_source_configuration,
)
from pamolive.policies.models import AccessPolicy, SecretRotationPolicy, TimeFrame
from pamolive.rbac.models import Role, UserGroup
from pamolive.rbac.permission_profiles import (
    PERMISSION_AREAS,
    capabilities_from_levels,
    level_for_capabilities,
    normalize_capabilities,
)
from pamolive.targets.models import Domain, Target, TargetGroup, TargetHostKey
from pamolive.targets.services import parse_ssh_public_key
from pamolive.vault.models import Credential
from pamolive.vault.services import VaultCipher


class ConsoleFormMixin:
    field_sections = ()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            widget = field.widget
            if isinstance(widget, forms.CheckboxSelectMultiple):
                widget.attrs["class"] = "choice-grid"
            elif isinstance(widget, forms.CheckboxInput):
                widget.attrs["class"] = "toggle-input"
            else:
                widget.attrs["class"] = "console-input"

    @property
    def sectioned_fields(self):
        sections = []
        for number, (title, description, field_names) in enumerate(
            self.field_sections, start=1
        ):
            fields = [self[name] for name in field_names if name in self.fields]
            if fields:
                sections.append(
                    {
                        "number": f"{number:02d}",
                        "title": title,
                        "description": description,
                        "fields": fields,
                    }
                )
        return sections


class PlatformSecurityPolicyForm(ConsoleFormMixin, forms.ModelForm):
    class Meta:
        model = PlatformSecurityPolicy
        fields = (
            "idle_timeout_minutes",
            "absolute_session_minutes",
            "require_mfa_for_all_users",
        )
        labels = {
            "idle_timeout_minutes": "Déconnexion après inactivité (minutes)",
            "absolute_session_minutes": "Durée maximale d’une session web (minutes)",
            "require_mfa_for_all_users": "MFA obligatoire pour tous les utilisateurs",
        }

    def clean(self):
        cleaned = super().clean()
        idle = cleaned.get("idle_timeout_minutes")
        absolute = cleaned.get("absolute_session_minutes")
        if idle and absolute and absolute < idle:
            self.add_error(
                "absolute_session_minutes",
                "La durée maximale doit être supérieure au délai d’inactivité.",
            )
        return cleaned


class SIEMIntegrationForm(ConsoleFormMixin, forms.ModelForm):
    auth_token = forms.CharField(
        label="Bearer token (optional)",
        required=False,
        widget=forms.PasswordInput(render_value=False),
        help_text="Stored encrypted. Leave empty to preserve the current token.",
    )

    class Meta:
        model = SIEMIntegration
        fields = ("name", "kind", "endpoint", "host", "port", "enabled")
        labels = {
            "name": "Integration name",
            "kind": "Transport",
            "endpoint": "HTTPS collector URL",
            "host": "Syslog host",
            "port": "Syslog TLS port",
            "enabled": "Forward new audit events",
        }

    def save(self, commit=True):
        integration = super().save(commit=False)
        integration.verify_tls = True
        token = self.cleaned_data.get("auth_token")
        if token:
            cipher = VaultCipher()
            integration.encrypted_auth_token = cipher.encrypt(token)
            integration.auth_token_encryption_key_id = cipher.active_key_id
        if commit:
            integration.full_clean()
            integration.save()
        return integration


class UserCreateForm(ConsoleFormMixin, UserCreationForm):
    class Meta(UserCreationForm.Meta):
        model = User
        fields = (
            "username",
            "display_name",
            "email",
            "is_active",
        )
        labels = {
            "username": "Identifiant",
            "display_name": "Nom affiché",
            "email": "Adresse e-mail",
            "is_active": "Compte actif",
        }


class UserUpdateForm(ConsoleFormMixin, forms.ModelForm):
    class Meta:
        model = User
        fields = ("username", "display_name", "email", "is_active")
        labels = {
            "username": "Identifiant",
            "display_name": "Nom affiché",
            "email": "Adresse e-mail",
            "is_active": "Compte actif",
        }


class UserGroupForm(ConsoleFormMixin, forms.ModelForm):
    class Meta:
        model = UserGroup
        fields = ("name", "description", "users", "roles", "enabled")
        labels = {
            "name": "Nom du groupe",
            "description": "Description",
            "users": "Membres",
            "roles": "Rôles attribués",
            "enabled": "Groupe actif",
        }
        widgets = {
            "users": forms.SelectMultiple(attrs={"size": 7}),
            "roles": forms.SelectMultiple(attrs={"size": 4}),
        }


class RoleForm(ConsoleFormMixin, forms.ModelForm):
    capabilities = forms.MultipleChoiceField(
        label="Compatibilité des droits",
        choices=Role.Capability.choices,
        widget=forms.MultipleHiddenInput,
        required=False,
    )

    field_sections = (
        (
            "Identité du profil",
            "Un profil décrit les fonctions administratives accessibles. "
            "Il ne donne pas accès aux cibles.",
            ("name", "slug", "description"),
        ),
        (
            "Identités et délégation",
            "Séparez la gestion des utilisateurs, des groupes, des profils et des annuaires.",
            tuple(
                area.field_name
                for area in PERMISSION_AREAS
                if area.section == "Identités et délégation"
            ),
        ),
        (
            "Ressources privilégiées",
            "Définissez ce que l’administrateur peut consulter ou configurer côté cibles.",
            tuple(
                area.field_name
                for area in PERMISSION_AREAS
                if area.section == "Ressources privilégiées"
            ),
        ),
        (
            "Secrets et autorisations",
            "La gestion des comptes, la révélation des secrets et les "
            "autorisations restent indépendantes.",
            tuple(
                area.field_name
                for area in PERMISSION_AREAS
                if area.section == "Secrets et autorisations"
            ),
        ),
        (
            "Exploitation et contrôle",
            "Accordez séparément approbations, supervision, audit et configuration système.",
            tuple(
                area.field_name
                for area in PERMISSION_AREAS
                if area.section == "Exploitation et contrôle"
            ),
        ),
        ("Activation", "Un profil inactif ne confère aucun droit.", ("enabled",)),
    )

    class Meta:
        model = Role
        fields = ("name", "slug", "description", "capabilities", "enabled")
        labels = {
            "name": "Nom du rôle",
            "slug": "Identifiant technique",
            "description": "Description",
            "enabled": "Rôle actif",
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        capabilities = self.instance.capabilities if self.instance.pk else ()
        for area in PERMISSION_AREAS:
            self.fields[area.field_name] = forms.ChoiceField(
                label=area.label,
                choices=((level.value, level.label) for level in area.levels),
                initial=level_for_capabilities(area, capabilities),
                required=False,
                help_text=area.help_text,
                widget=forms.Select(attrs={"class": "console-input permission-level-select"}),
            )

    def clean(self):
        cleaned = super().clean()
        if self.instance.is_system and self.has_changed():
            protected_fields = {"name", "slug", "capabilities", "enabled"}
            if protected_fields.intersection(self.changed_data):
                raise forms.ValidationError(
                    "Les profils système sont versionnés et ne peuvent pas être modifiés ici."
                )
        level_fields_were_submitted = any(
            area.field_name in self.data for area in PERMISSION_AREAS
        )
        if level_fields_were_submitted:
            cleaned["capabilities"] = capabilities_from_levels(cleaned)
        else:
            cleaned["capabilities"] = normalize_capabilities(
                cleaned.get("capabilities", ())
            )
        return cleaned

    def save(self, commit=True):
        role = super().save(commit=False)
        role.capabilities = self.cleaned_data["capabilities"]
        if commit:
            role.save()
            self.save_m2m()
        return role


class IdentitySourceForm(ConsoleFormMixin, forms.ModelForm):
    source_kind = None
    server_uri = forms.CharField(label="Adresse du serveur LDAP", required=False)
    bind_dn = forms.CharField(label="Compte de liaison", required=False)
    bind_password = forms.CharField(
        label="Mot de passe de liaison",
        required=False,
        widget=forms.PasswordInput(render_value=False),
        help_text="Laissez vide pour conserver le secret existant.",
    )
    base_dn = forms.CharField(label="Base de recherche", required=False)
    user_filter = forms.CharField(label="Filtre des utilisateurs", required=False)
    group_filter = forms.CharField(label="Filtre des groupes", required=False)
    issuer = forms.URLField(label="Émetteur OIDC", required=False)
    client_id = forms.CharField(label="Client ID", required=False)
    client_secret = forms.CharField(
        label="Secret client",
        required=False,
        widget=forms.PasswordInput(render_value=False),
        help_text="Laissez vide pour conserver le secret existant.",
    )
    scopes = forms.CharField(label="Scopes OIDC", required=False, initial="openid email profile")
    groups_claim = forms.CharField(label="Claim des groupes", required=False, initial="groups")
    allowed_email_domains = forms.CharField(
        label="Domaines e-mail autorisés",
        required=False,
        help_text="Séparez plusieurs domaines par des virgules, par exemple mopacy.be, mopacy.eu.",
    )
    allowed_emails = forms.CharField(
        label="Adresses e-mail autorisées",
        required=False,
        widget=forms.Textarea(attrs={"rows": 3}),
        help_text="Optionnel : une adresse par ligne ou séparée par virgule.",
    )
    default_user_group = forms.ModelChoiceField(
        label="Groupe PamOlive par défaut",
        queryset=UserGroup.objects.filter(enabled=True).order_by("name"),
        required=False,
        help_text="Groupe attribué quand le fournisseur ne renvoie pas de groupes.",
    )

    class Meta:
        model = IdentitySource
        fields = (
            "name",
            "slug",
            "kind",
            "enabled",
            "sync_enabled",
            "sync_interval_minutes",
        )
        labels = {
            "name": "Nom de la source",
            "slug": "Identifiant technique",
            "kind": "Type de source",
            "enabled": "Source active",
            "sync_enabled": "Synchronisation automatique",
            "sync_interval_minutes": "Intervalle de synchronisation (minutes)",
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.source_kind:
            self.fields["kind"].initial = self.source_kind
            self.fields["kind"].widget = forms.HiddenInput()
            if self.source_kind == IdentitySource.Kind.OIDC:
                for field_name in (
                    "server_uri", "bind_dn", "bind_password", "base_dn",
                    "user_filter", "group_filter", "sync_enabled",
                    "sync_interval_minutes",
                ):
                    self.fields.pop(field_name, None)
            else:
                for field_name in (
                    "issuer", "client_id", "client_secret", "scopes", "groups_claim",
                    "allowed_email_domains", "allowed_emails", "default_user_group"
                ):
                    self.fields.pop(field_name, None)
        if self.instance.pk and self.instance.encrypted_configuration:
            configuration = get_identity_source_configuration(self.instance)
            for field_name in self.fields:
                if field_name in configuration and field_name not in {
                    "bind_password",
                    "client_secret",
                    "default_user_group",
                }:
                    self.fields[field_name].initial = configuration[field_name]
            if "default_user_group" in self.fields and configuration.get("default_user_group"):
                self.fields["default_user_group"].initial = configuration["default_user_group"]

    def clean(self):
        cleaned = super().clean()
        kind = self.source_kind or cleaned.get("kind")
        cleaned["kind"] = kind
        if not kind:
            return cleaned
        existing = {}
        if self.instance.pk and self.instance.encrypted_configuration:
            existing = get_identity_source_configuration(self.instance)
        if kind in {IdentitySource.Kind.LDAP, IdentitySource.Kind.ACTIVE_DIRECTORY}:
            configuration = {
                "server_uri": cleaned.get("server_uri"),
                "bind_dn": cleaned.get("bind_dn", ""),
                "bind_password": cleaned.get("bind_password") or existing.get("bind_password", ""),
                "base_dn": cleaned.get("base_dn"),
                "user_filter": cleaned.get("user_filter"),
                "group_filter": cleaned.get("group_filter", ""),
                "username_attribute": existing.get("username_attribute", "sAMAccountName"),
                "email_attribute": existing.get("email_attribute", "mail"),
                "display_name_attribute": existing.get("display_name_attribute", "displayName"),
                "group_attribute": existing.get("group_attribute", "memberOf"),
                "use_start_tls": existing.get("use_start_tls", False),
                "connect_timeout_seconds": existing.get("connect_timeout_seconds", 10),
            }
        else:
            configuration = {
                "issuer": cleaned.get("issuer"),
                "client_id": cleaned.get("client_id"),
                "client_secret": cleaned.get("client_secret") or existing.get("client_secret", ""),
                "scopes": cleaned.get("scopes") or "openid email profile",
                "username_claim": existing.get("username_claim", "preferred_username"),
                "email_claim": existing.get("email_claim", "email"),
                "display_name_claim": existing.get("display_name_claim", "name"),
                "groups_claim": cleaned.get("groups_claim") or "groups",
                "allowed_email_domains": cleaned.get("allowed_email_domains", ""),
                "allowed_emails": cleaned.get("allowed_emails", ""),
                "default_user_group": (
                    str(cleaned["default_user_group"].pk)
                    if cleaned.get("default_user_group")
                    else existing.get("default_user_group", "")
                ),
            }
        try:
            cleaned["configuration"] = validate_identity_source_configuration(kind, configuration)
        except forms.ValidationError as error:
            self.add_error(None, error)
        return cleaned

    def save(self, commit=True):
        source = super().save(commit=False)
        source.verify_tls = True
        set_identity_source_configuration(source, self.cleaned_data["configuration"])
        if commit:
            source.save()
        return source


class LDAPIdentitySourceForm(IdentitySourceForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["kind"].choices = (
            (IdentitySource.Kind.LDAP, "LDAP"),
            (IdentitySource.Kind.ACTIVE_DIRECTORY, "Microsoft Active Directory"),
        )
        for field_name in (
            "issuer", "client_id", "client_secret", "scopes", "groups_claim"
        ):
            self.fields.pop(field_name, None)


class OIDCIdentitySourceForm(IdentitySourceForm):
    source_kind = IdentitySource.Kind.OIDC


class DirectoryGroupMappingForm(ConsoleFormMixin, forms.ModelForm):
    class Meta:
        model = DirectoryGroupMapping
        fields = ("source", "external_group", "user_group", "auto_create_users", "enabled")
        labels = {
            "source": "Source d’identité",
            "external_group": "Groupe externe",
            "user_group": "Groupe PAM-olive",
            "auto_create_users": "Créer automatiquement les utilisateurs",
            "enabled": "Correspondance active",
        }


class DomainForm(ConsoleFormMixin, forms.ModelForm):
    class Meta:
        model = Domain
        fields = ("name", "kind", "dns_name", "description", "enabled")
        labels = {
            "name": "Nom du domaine",
            "kind": "Type",
            "dns_name": "Nom DNS",
            "description": "Description",
            "enabled": "Domaine actif",
        }


class TargetForm(ConsoleFormMixin, forms.ModelForm):
    credential_name = forms.CharField(label="Nom de l’identifiant local", required=False)
    credential_username = forms.CharField(label="Utilisateur local", required=False)
    credential_password = forms.CharField(
        label="Mot de passe local", required=False, widget=forms.PasswordInput
    )
    credential_totp = forms.CharField(label="Secret TOTP associé", required=False)

    class Meta:
        model = Target
        fields = (
            "name",
            "kind",
            "domain",
            "hostname",
            "port",
            "protocol",
            "ssh_host_key_policy",
            "platform",
            "description",
            "rdp_security",
            "rdp_certificate_fingerprints",
            "rdp_server_layout",
            "rdp_resize_method",
            "enabled",
        )
        labels = {
            "name": "Nom de la cible",
            "kind": "Type de cible",
            "domain": "Domaine",
            "hostname": "Nom d’hôte ou adresse IP",
            "port": "Port",
            "protocol": "Protocole",
            "ssh_host_key_policy": "Vérification de l’identité SSH",
            "platform": "Plateforme",
            "description": "Description",
            "rdp_security": "Sécurité RDP",
            "rdp_certificate_fingerprints": "Empreintes de certificat RDP",
            "rdp_server_layout": "Disposition clavier du serveur RDP",
            "rdp_resize_method": "Redimensionnement RDP",
            "enabled": "Cible active",
        }
        help_texts = {
            "rdp_certificate_fingerprints": (
                "Une empreinte FreeRDP par ligne. Laisser vide uniquement si le certificat "
                "de la cible est validé par une autorité reconnue."
            ),
            "rdp_server_layout": "Exemple pour la Belgique : fr-be-azerty.",
        }
        widgets = {"rdp_certificate_fingerprints": forms.Textarea(attrs={"rows": 3})}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["kind"].widget = forms.HiddenInput()
        self.fields["protocol"].choices = (
            (Target.Protocol.SSH, "SSH"),
            (Target.Protocol.RDP, "RDP"),
        )
        self.fields["kind"].required = False
        self.fields["kind"].initial = Target.Kind.DEVICE
        self.fields["ssh_host_key_policy"].required = False
        self.fields["ssh_host_key_policy"].initial = (
            Target.SSHHostKeyPolicy.TRUST_ON_FIRST_USE
        )
        rdp_defaults = {
            "rdp_security": Target.RDPSecurity.NLA,
            "rdp_server_layout": "fr-be-azerty",
            "rdp_resize_method": Target.RDPResizeMethod.DISPLAY_UPDATE,
        }
        for name, initial in rdp_defaults.items():
            self.fields[name].required = False
            self.fields[name].initial = initial
        self.fields["rdp_certificate_fingerprints"].required = False
        creating = self.instance._state.adding
        for name in ("credential_name", "credential_username", "credential_password"):
            self.fields[name].required = creating

    def clean(self):
        cleaned = super().clean()
        cleaned["kind"] = Target.Kind.DEVICE
        cleaned["ssh_host_key_policy"] = (
            cleaned.get("ssh_host_key_policy")
            or Target.SSHHostKeyPolicy.TRUST_ON_FIRST_USE
        )
        if cleaned.get("protocol") not in {Target.Protocol.SSH, Target.Protocol.RDP}:
            self.add_error("protocol", "Seuls les équipements SSH et RDP sont disponibles.")
        if cleaned.get("protocol") == Target.Protocol.RDP:
            cleaned["rdp_security"] = cleaned.get("rdp_security") or Target.RDPSecurity.NLA
            cleaned["rdp_server_layout"] = cleaned.get("rdp_server_layout") or "fr-be-azerty"
            cleaned["rdp_resize_method"] = (
                cleaned.get("rdp_resize_method") or Target.RDPResizeMethod.DISPLAY_UPDATE
            )
            fingerprints = [
                value.strip()
                for value in cleaned.get("rdp_certificate_fingerprints", "")
                .replace(",", "\n")
                .splitlines()
                if value.strip()
            ]
            cleaned["rdp_certificate_fingerprints"] = ",".join(fingerprints)
        return cleaned

    def save_initial_credential(self, target):
        if not self.cleaned_data.get("credential_password"):
            return None
        cipher = VaultCipher()
        return Credential.objects.create(
            target=target,
            name=self.cleaned_data["credential_name"],
            username=self.cleaned_data["credential_username"],
            domain=target.domain,
            kind=Credential.Kind.PASSWORD,
            encrypted_secret=cipher.encrypt(self.cleaned_data["credential_password"]),
            secret_encryption_key_id=cipher.active_key_id,
            encrypted_totp_secret=(
                cipher.encrypt(self.cleaned_data["credential_totp"])
                if self.cleaned_data.get("credential_totp")
                else None
            ),
            totp_encryption_key_id=cipher.active_key_id,
        )


class TargetGroupForm(ConsoleFormMixin, forms.ModelForm):
    class Meta:
        model = TargetGroup
        fields = ("name", "description", "targets", "enabled")
        labels = {
            "name": "Nom du groupe",
            "description": "Description",
            "targets": "Cibles membres",
            "enabled": "Groupe actif",
        }
        widgets = {"targets": forms.SelectMultiple(attrs={"size": 8})}


class TargetHostKeyForm(ConsoleFormMixin, forms.ModelForm):
    class Meta:
        model = TargetHostKey
        fields = ("target", "public_key", "comment")
        labels = {
            "target": "Cible SSH",
            "public_key": "Clé publique d’hôte OpenSSH",
            "comment": "Justification ou source de confiance",
        }
        widgets = {"public_key": forms.Textarea(attrs={"rows": 4})}

    def clean_target(self):
        target = self.cleaned_data["target"]
        if target.protocol != Target.Protocol.SSH:
            raise forms.ValidationError("Une clé d’hôte ne peut être liée qu’à une cible SSH.")
        return target

    def clean_public_key(self):
        _key_type, normalized, _fingerprint = parse_ssh_public_key(
            self.cleaned_data["public_key"]
        )
        return normalized


class AccessPolicyForm(ConsoleFormMixin, forms.ModelForm):
    actions = forms.MultipleChoiceField(
        label="Actions autorisées",
        choices=(
            (AccessPolicy.Action.REQUEST_ACCESS, "Demander un accès"),
            (AccessPolicy.Action.START_SESSION, "Démarrer une session"),
            (AccessPolicy.Action.VIEW_SECRET, "Consulter un secret"),
            (AccessPolicy.Action.REVEAL_TOTP, "Consulter un code TOTP"),
        ),
        widget=forms.SelectMultiple(attrs={"size": 6}),
        required=True,
        help_text=(
            "Les droits d’administration sont définis dans les profils de permissions, "
            "jamais ici."
        ),
    )
    protocols = forms.MultipleChoiceField(
        label="Protocoles autorisés",
        choices=((Target.Protocol.SSH, "SSH"), (Target.Protocol.RDP, "RDP")),
        widget=forms.SelectMultiple(attrs={"size": 2}),
        required=False,
        help_text="Vide : tous les protocoles des cibles liées.",
    )
    source_cidrs = forms.CharField(
        label="Réseaux sources autorisés",
        required=False,
        widget=forms.Textarea(attrs={"rows": 3}),
        help_text="Un CIDR par ligne ou séparé par une virgule. Vide : toute origine.",
    )

    field_sections = (
        (
            "Bénéficiaires",
            "Qui reçoit cette autorisation ? Un utilisateur peut cumuler plusieurs groupes.",
            ("name", "user_groups"),
        ),
        (
            "Ressources autorisées",
            "À quels groupes de cibles, comptes et protocoles l’autorisation s’applique-t-elle ?",
            ("target_groups", "credentials", "protocols"),
        ),
        (
            "Usages accordés",
            "Choisissez uniquement les opérations que les bénéficiaires peuvent "
            "demander ou exécuter.",
            ("actions",),
        ),
        (
            "Circuit d’approbation",
            "Définissez les approbateurs, le quorum et la référence métier attendue.",
            ("requires_approval", "approver_groups", "approval_quorum", "ticket_required"),
        ),
        (
            "Sécurité de session",
            "Appliquez MFA, durée, concurrence et presse-papiers à toutes les sessions couvertes.",
            (
                "requires_mfa",
                "max_duration_minutes",
                "max_concurrent_sessions",
                "allow_clipboard_copy",
                "allow_clipboard_paste",
            ),
        ),
        (
            "Calendrier et origine",
            "Limitez l’autorisation à des plages réutilisables, une période et des "
            "réseaux sources.",
            ("time_frames", "valid_from", "valid_until", "source_cidrs"),
        ),
        ("Activation", "Une autorisation inactive ne donne aucun accès.", ("enabled",)),
    )

    class Meta:
        model = AccessPolicy
        fields = (
            "name",
            "user_groups",
            "target_groups",
            "credentials",
            "approver_groups",
            "time_frames",
            "actions",
            "protocols",
            "requires_approval",
            "approval_quorum",
            "ticket_required",
            "requires_mfa",
            "max_duration_minutes",
            "max_concurrent_sessions",
            "allow_clipboard_copy",
            "allow_clipboard_paste",
            "valid_from",
            "valid_until",
            "source_cidrs",
            "enabled",
        )
        labels = {
            "name": "Nom de la politique",
            "user_groups": "Groupes d’utilisateurs",
            "target_groups": "Groupes de cibles",
            "credentials": "Comptes privilégiés concernés",
            "approver_groups": "Groupes d’approbateurs",
            "time_frames": "Plages horaires",
            "requires_approval": "Approbation obligatoire",
            "approval_quorum": "Nombre d’approbations requises",
            "ticket_required": "Référence de ticket obligatoire",
            "requires_mfa": "MFA obligatoire",
            "max_duration_minutes": "Durée maximale (minutes)",
            "max_concurrent_sessions": "Sessions simultanées maximales",
            "allow_clipboard_copy": "Autoriser la copie depuis la session",
            "allow_clipboard_paste": "Autoriser le collage vers la session",
            "valid_from": "Valide à partir de",
            "valid_until": "Valide jusqu’au",
            "enabled": "Politique active",
        }
        widgets = {
            "user_groups": forms.SelectMultiple(attrs={"size": 6}),
            "target_groups": forms.SelectMultiple(attrs={"size": 6}),
            "credentials": forms.SelectMultiple(attrs={"size": 6}),
            "approver_groups": forms.SelectMultiple(attrs={"size": 6}),
            "time_frames": forms.SelectMultiple(attrs={"size": 5}),
            "valid_from": forms.DateTimeInput(attrs={"type": "datetime-local"}),
            "valid_until": forms.DateTimeInput(attrs={"type": "datetime-local"}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["approval_quorum"].required = False
        self.fields["approval_quorum"].initial = 1
        self.fields["max_concurrent_sessions"].required = False
        self.fields["max_concurrent_sessions"].initial = 1
        if self.instance.pk and not self.is_bound:
            self.initial["source_cidrs"] = "\n".join(self.instance.source_cidrs)

    def clean(self):
        cleaned = super().clean()
        cleaned["approval_quorum"] = cleaned.get("approval_quorum") or 1
        cleaned["max_concurrent_sessions"] = cleaned.get("max_concurrent_sessions") or 1
        cidr_text = cleaned.get("source_cidrs", "")
        cidrs = [item.strip() for item in cidr_text.replace(",", "\n").splitlines() if item.strip()]
        for cidr in cidrs:
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                self.add_error("source_cidrs", f"Le réseau « {cidr} » n’est pas un CIDR valide.")
        cleaned["source_cidrs"] = cidrs
        if not cleaned.get("user_groups"):
            self.add_error("user_groups", "Sélectionnez au moins un groupe d’utilisateurs.")
        if not cleaned.get("target_groups"):
            self.add_error("target_groups", "Sélectionnez au moins un groupe de cibles.")
        if cleaned.get("requires_approval") and cleaned.get("approval_quorum", 0) < 1:
            self.add_error("approval_quorum", "Le quorum doit être au moins égal à 1.")
        if (
            cleaned.get("valid_from")
            and cleaned.get("valid_until")
            and cleaned["valid_from"] >= cleaned["valid_until"]
        ):
            self.add_error("valid_until", "La fin de validité doit être postérieure au début.")
        return cleaned


class TimeFrameForm(ConsoleFormMixin, forms.ModelForm):
    weekdays = forms.MultipleChoiceField(
        label="Jours actifs",
        choices=((0, "Lundi"), (1, "Mardi"), (2, "Mercredi"), (3, "Jeudi"),
                 (4, "Vendredi"), (5, "Samedi"), (6, "Dimanche")),
        widget=forms.SelectMultiple(attrs={"size": 7}),
        required=False,
        help_text="Aucun jour sélectionné signifie tous les jours.",
    )

    class Meta:
        model = TimeFrame
        fields = (
            "name", "weekdays", "start_time", "end_time", "valid_from", "valid_until", "enabled"
        )
        labels = {
            "name": "Nom de la plage",
            "start_time": "Heure de début",
            "end_time": "Heure de fin",
            "valid_from": "Valide à partir de",
            "valid_until": "Valide jusqu’au",
            "enabled": "Plage active",
        }
        widgets = {
            "start_time": forms.TimeInput(attrs={"type": "time"}),
            "end_time": forms.TimeInput(attrs={"type": "time"}),
            "valid_from": forms.DateTimeInput(attrs={"type": "datetime-local"}),
            "valid_until": forms.DateTimeInput(attrs={"type": "datetime-local"}),
        }

    def clean_weekdays(self):
        return [int(day) for day in self.cleaned_data["weekdays"]]

    def clean(self):
        cleaned = super().clean()
        if cleaned.get("valid_from") and cleaned.get("valid_until"):
            if cleaned["valid_from"] >= cleaned["valid_until"]:
                self.add_error("valid_until", "La fin doit être postérieure au début.")
        return cleaned


class SecretRotationPolicyForm(ConsoleFormMixin, forms.ModelForm):
    class Meta:
        model = SecretRotationPolicy
        fields = (
            "name", "target_groups", "strategy", "interval_days", "password_length",
            "connector_key", "enabled",
        )
        labels = {
            "name": "Nom de la politique",
            "target_groups": "Groupes de cibles",
            "strategy": "Méthode de rotation",
            "interval_days": "Fréquence (jours)",
            "password_length": "Longueur du mot de passe",
            "connector_key": "Connecteur d’exécution",
            "enabled": "Politique active",
        }
        help_texts = {
            "connector_key": (
                "Identifiant interne du connecteur chargé de modifier le compte distant."
            ),
        }
        widgets = {"target_groups": forms.SelectMultiple(attrs={"size": 7})}


class TargetCredentialForm(ConsoleFormMixin, forms.ModelForm):
    secret = forms.CharField(
        label="Mot de passe ou clé", required=False, widget=forms.PasswordInput
    )
    totp_secret = forms.CharField(label="Secret TOTP associé", required=False)

    class Meta:
        model = Credential
        fields = (
            "name",
            "target",
            "domain",
            "username",
            "account_type",
            "kind",
            "checkout_enabled",
            "rotation_policy",
        )
        labels = {
            "name": "Nom de l’identifiant",
            "target": "Cible",
            "domain": "Domaine",
            "username": "Utilisateur local",
            "account_type": "Type de compte",
            "kind": "Type",
            "checkout_enabled": "Consultation autorisée",
            "rotation_policy": "Politique de rotation automatique",
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["account_type"].required = False
        self.fields["account_type"].initial = Credential.AccountType.LOCAL
        self.fields["account_type"].choices = (
            (Credential.AccountType.LOCAL, "Compte local"),
            (Credential.AccountType.DOMAIN, "Compte de domaine"),
            (Credential.AccountType.SERVICE, "Compte de service"),
        )
        self.fields["kind"].choices = (
            (Credential.Kind.PASSWORD, "Mot de passe"),
            (Credential.Kind.SSH_KEY, "Clé privée SSH"),
        )

    def clean(self):
        cleaned = super().clean()
        if self.instance._state.adding and not cleaned.get("secret"):
            self.add_error("secret", "Le secret est obligatoire.")
        if cleaned.get("account_type") == Credential.AccountType.DOMAIN and not cleaned.get(
            "domain"
        ):
            self.add_error("domain", "Un compte de domaine doit référencer un domaine.")
        return cleaned

    def save(self, commit=True):
        credential = super().save(commit=False)
        cipher = VaultCipher()
        if self.cleaned_data.get("secret"):
            credential.encrypted_secret = cipher.encrypt(self.cleaned_data["secret"])
            credential.secret_encryption_key_id = cipher.active_key_id
        if self.cleaned_data.get("totp_secret"):
            credential.encrypted_totp_secret = cipher.encrypt(self.cleaned_data["totp_secret"])
            credential.totp_encryption_key_id = cipher.active_key_id
        if credential.rotation_policy_id:
            credential.rotation_enabled = False
            credential.rotation_interval_days = None
            credential.rotation_backend = ""
            if not credential.next_rotation_at:
                credential.next_rotation_at = timezone.now()
            elif "rotation_policy" in self.changed_data and credential.last_rotated_at:
                credential.next_rotation_at = credential.last_rotated_at + timedelta(
                    days=credential.rotation_policy.interval_days
                )
        else:
            credential.next_rotation_at = None
        if commit:
            credential.save()
        return credential

from authlib.integrations.django_client import OAuth
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.utils import timezone

from pamolive.accounts.models import User
from pamolive.rbac.models import UserGroup

from .models import ExternalIdentity, IdentitySource
from .services import get_identity_source_configuration
from .sync import reconcile_external_memberships, reconcile_oidc_default_membership


class OIDCProvisioningError(PermissionDenied):
    pass


def oidc_client_for(source):
    if source.kind != IdentitySource.Kind.OIDC or not source.enabled:
        raise OIDCProvisioningError("Le fournisseur OIDC n’est pas disponible.")
    configuration = get_identity_source_configuration(source)
    oauth = OAuth()
    client = oauth.register(
        name=f"pam_olive_{source.slug}",
        client_id=configuration["client_id"],
        client_secret=configuration["client_secret"],
        server_metadata_url=(
            f"{configuration['issuer'].rstrip('/')}/.well-known/openid-configuration"
        ),
        client_kwargs={"scope": configuration.get("scopes", "openid email profile")},
    )
    return client


def _claim(configuration, claims, name, default):
    return claims.get(configuration.get(name, default))


def _normalized_csv(value):
    if not value:
        return set()
    if isinstance(value, str):
        values = value.replace("\n", ",").split(",")
    else:
        values = value
    return {str(item).strip().casefold() for item in values if str(item).strip()}


def _email_allowed_by_configuration(configuration, email):
    email = (email or "").strip().casefold()
    if not email or "@" not in email:
        return False
    email_domain = email.rsplit("@", 1)[1]
    allowed_emails = _normalized_csv(configuration.get("allowed_emails", ""))
    allowed_domains = {
        domain.lstrip("@")
        for domain in _normalized_csv(configuration.get("allowed_email_domains", ""))
    }
    return email in allowed_emails or email_domain in allowed_domains


def _default_group(configuration):
    group_id = configuration.get("default_user_group")
    if not group_id:
        return None
    return UserGroup.objects.filter(pk=group_id, enabled=True).first()


@transaction.atomic
def _provision_oidc_identity(source, claims):
    if source.kind != IdentitySource.Kind.OIDC or not source.enabled:
        raise OIDCProvisioningError("Le fournisseur OIDC n’est pas disponible.")
    subject = claims.get("sub")
    if not subject:
        raise OIDCProvisioningError("Le jeton OIDC ne contient pas de sujet.")

    configuration = get_identity_source_configuration(source)
    username = _claim(configuration, claims, "username_claim", "preferred_username")
    email = _claim(configuration, claims, "email_claim", "email") or ""
    display_name = _claim(configuration, claims, "display_name_claim", "name") or ""
    groups = _claim(configuration, claims, "groups_claim", "groups") or []
    if isinstance(groups, str):
        groups = [groups]
    if not username:
        raise OIDCProvisioningError("Le fournisseur OIDC n’a pas fourni d’identifiant utilisateur.")

    identity = ExternalIdentity.objects.select_related("user").filter(
        source=source,
        subject=subject,
    ).first()
    mappings = list(source.group_mappings.filter(enabled=True).select_related("user_group"))
    group_names = {str(group).strip().casefold() for group in groups}
    matched = [
        mapping
        for mapping in mappings
        if mapping.external_group.strip().casefold() in group_names
    ]
    default_group = _default_group(configuration)
    fallback_authorized = bool(
        claims.get("email_verified") is True
        and default_group
        and _email_allowed_by_configuration(configuration, email)
    )

    if identity is None:
        if (
            (not matched or not any(mapping.auto_create_users for mapping in matched))
            and not fallback_authorized
        ):
            raise OIDCProvisioningError(
                "Aucun groupe, e-mail ou domaine OIDC n’autorise la création de ce compte."
            )
        if User.objects.filter(username=username).exists():
            raise OIDCProvisioningError(
                "Un compte local porte déjà cet identifiant ; une liaison manuelle est requise."
            )
        if email and User.objects.filter(email=email).exists():
            raise OIDCProvisioningError(
                "Un compte local utilise déjà cette adresse ; une liaison manuelle est requise."
            )
        user = User(username=username, email=email, display_name=display_name, is_active=True)
        user.set_unusable_password()
        user.save()
        identity = ExternalIdentity.objects.create(
            source=source,
            user=user,
            subject=subject,
            username=username,
            email=email,
            claims=claims,
            last_seen_at=timezone.now(),
        )
    else:
        if not identity.enabled or not identity.user.is_active:
            raise OIDCProvisioningError("Ce compte externe est désactivé.")
        identity.username = username
        identity.email = email
        identity.claims = claims
        identity.last_seen_at = timezone.now()
        identity.save(
            update_fields=(
                "username",
                "email",
                "claims",
                "last_seen_at",
                "updated_at",
            )
        )

    reconcile_external_memberships(identity, matched)
    reconcile_oidc_default_membership(identity, default_group if fallback_authorized else None)
    return identity.user, bool(matched or fallback_authorized)


def provision_oidc_identity(source, claims):
    user, authorized = _provision_oidc_identity(source, claims)
    if not authorized:
        raise OIDCProvisioningError("Aucun groupe OIDC n’autorise actuellement ce compte.")
    return user

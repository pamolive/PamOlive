from authlib.integrations.django_client import OAuth
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.utils import timezone

from pamolive.accounts.models import User

from .models import ExternalIdentity, IdentitySource
from .services import get_identity_source_configuration
from .sync import reconcile_external_memberships


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


@transaction.atomic
def _provision_oidc_identity(source, claims):
    if source.kind != IdentitySource.Kind.OIDC or not source.enabled:
        raise OIDCProvisioningError("Le fournisseur OIDC n’est pas disponible.")
    if claims.get("email_verified") is False:
        raise OIDCProvisioningError(
            "L’adresse e-mail fournie par le fournisseur n’est pas vérifiée."
        )
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

    if identity is None:
        if not matched or not any(mapping.auto_create_users for mapping in matched):
            raise OIDCProvisioningError("Aucun groupe OIDC n’autorise la création de ce compte.")
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
        identity.username = username
        identity.email = email
        identity.claims = claims
        identity.enabled = True
        identity.last_seen_at = timezone.now()
        identity.save(
            update_fields=(
                "username",
                "email",
                "claims",
                "enabled",
                "last_seen_at",
                "updated_at",
            )
        )

    reconcile_external_memberships(identity, matched)
    if not identity.enabled or not identity.user.is_active:
        raise OIDCProvisioningError("Ce compte externe est désactivé.")
    return identity.user, bool(matched)


def provision_oidc_identity(source, claims):
    user, authorized = _provision_oidc_identity(source, claims)
    if not authorized:
        raise OIDCProvisioningError("Aucun groupe OIDC n’autorise actuellement ce compte.")
    return user

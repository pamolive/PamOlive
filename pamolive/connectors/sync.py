from dataclasses import asdict

from django.db import transaction
from django.utils import timezone

from pamolive.accounts.models import User
from pamolive.audit.services import record_event

from .adapters import adapter_for
from .models import ExternalGroupMembership, ExternalIdentity, IdentitySource


class DirectorySynchronizationError(RuntimeError):
    pass


def _normalized(value):
    return value.strip().casefold()


def _create_external_user(source, directory_user):
    if User.objects.filter(username=directory_user.username).exists():
        raise DirectorySynchronizationError(
            f"L’identifiant local {directory_user.username!r} existe déjà et ne peut pas être lié "
            "automatiquement."
        )
    if directory_user.email and User.objects.filter(email=directory_user.email).exists():
        raise DirectorySynchronizationError(
            f"L’adresse {directory_user.email!r} existe déjà et ne peut pas être liée "
            "automatiquement."
        )
    user = User(
        username=directory_user.username,
        email=directory_user.email,
        display_name=directory_user.display_name,
        is_active=True,
    )
    user.set_unusable_password()
    user.save()
    return ExternalIdentity.objects.create(
        source=source,
        user=user,
        subject=directory_user.subject,
        username=directory_user.username,
        email=directory_user.email,
        claims=directory_user.claims,
        last_seen_at=timezone.now(),
    )


def reconcile_external_memberships(identity, matched_mappings):
    matched_ids = {mapping.pk for mapping in matched_mappings}
    existing = list(
        identity.managed_group_memberships.select_related("mapping__user_group")
    )
    existing_mapping_ids = {membership.mapping_id for membership in existing}
    added = removed = 0

    for mapping in matched_mappings:
        if mapping.pk in existing_mapping_ids:
            continue
        was_member = mapping.user_group.users.filter(pk=identity.user_id).exists()
        ExternalGroupMembership.objects.create(
            identity=identity,
            mapping=mapping,
            preserve_membership_on_unlink=was_member,
        )
        if not was_member:
            mapping.user_group.users.add(identity.user_id)
            added += 1

    for membership in existing:
        if membership.mapping_id in matched_ids:
            continue
        user_group = membership.mapping.user_group
        preserve = membership.preserve_membership_on_unlink
        membership.delete()
        has_other_managed_source = ExternalGroupMembership.objects.filter(
            identity__user_id=identity.user_id,
            mapping__user_group=user_group,
        ).exists()
        if not preserve and not has_other_managed_source:
            user_group.users.remove(identity.user_id)
            removed += 1
    return added, removed


@transaction.atomic
def _apply_directory_users(source, directory_users):
    mappings = list(source.group_mappings.filter(enabled=True).select_related("user_group"))
    mappings_by_group = {_normalized(mapping.external_group): mapping for mapping in mappings}
    created = updated = skipped = memberships = memberships_removed = 0

    for directory_user in directory_users:
        matched = [
            mappings_by_group[_normalized(group)]
            for group in directory_user.groups
            if _normalized(group) in mappings_by_group
        ]
        external_identity = ExternalIdentity.objects.select_related("user").filter(
            source=source, subject=directory_user.subject
        ).first()
        if external_identity is None:
            if not matched or not any(mapping.auto_create_users for mapping in matched):
                skipped += 1
                continue
            external_identity = _create_external_user(source, directory_user)
            created += 1
        else:
            external_identity.username = directory_user.username
            external_identity.email = directory_user.email
            external_identity.claims = directory_user.claims
            external_identity.enabled = True
            external_identity.last_seen_at = timezone.now()
            external_identity.save(
                update_fields=(
                    "username",
                    "email",
                    "claims",
                    "enabled",
                    "last_seen_at",
                    "updated_at",
                )
            )
            updated += 1

        added, removed = reconcile_external_memberships(external_identity, matched)
        memberships += added
        memberships_removed += removed

    return {
        "created": created,
        "updated": updated,
        "skipped": skipped,
        "memberships_added": memberships,
        "memberships_removed": memberships_removed,
    }


def synchronize_identity_source(source, adapter=None):
    if not source.enabled:
        raise DirectorySynchronizationError("La source d’identité est désactivée.")
    source.last_sync_status = IdentitySource.SyncStatus.RUNNING
    source.last_error = ""
    source.save(update_fields=("last_sync_status", "last_error", "updated_at"))
    try:
        directory_users = (adapter or adapter_for(source)).fetch_users()
        result = _apply_directory_users(source, directory_users)
    except Exception as error:
        source.last_sync_status = IdentitySource.SyncStatus.FAILED
        source.last_sync_at = timezone.now()
        source.last_error = str(error)[:2000]
        source.save(
            update_fields=("last_sync_status", "last_sync_at", "last_error", "updated_at")
        )
        record_event(
            actor=None,
            action="identity_source.sync.failed",
            resource=source,
            metadata={"error_type": error.__class__.__name__},
        )
        raise

    source.last_sync_status = IdentitySource.SyncStatus.SUCCESS
    source.last_sync_at = timezone.now()
    source.last_error = ""
    source.save(
        update_fields=("last_sync_status", "last_sync_at", "last_error", "updated_at")
    )
    record_event(
        actor=None,
        action="identity_source.sync.completed",
        resource=source,
        metadata=result,
    )
    return result


def serialize_directory_user(directory_user):
    return asdict(directory_user)

import json

import pytest
from cryptography.fernet import Fernet
from django.core.management import call_command
from django.db import connection
from django.db.migrations.executor import MigrationExecutor

V02_MIGRATION_TARGETS = [
    ("accounts", "0001_initial"),
    ("approvals", "0003_accessrequest_ticket_reference_approvaldecision"),
    ("audit", "0002_audit_chain_v2"),
    ("connectors", "0004_encryption_key_identifiers"),
    ("mfa", "0002_mfadevice_encryption_key_id"),
    ("operations", "0002_rotationjob_candidate_encryption_key_id"),
    ("policies", "0006_accesspolicy_rdp_clipboard_controls"),
    ("rbac", "0006_expand_system_roles"),
    ("privileged_sessions", "0003_privilegedsession_termination_requested_at_and_more"),
    ("targets", "0005_target_rdp_security_options"),
    ("vault", "0007_encryption_key_identifiers"),
]
LEGACY_KEY = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="


@pytest.mark.django_db(transaction=True)
def test_v02_schema_and_encrypted_data_upgrade_without_loss(monkeypatch):
    executor = MigrationExecutor(connection)
    latest_targets = executor.loader.graph.leaf_nodes()

    try:
        executor.migrate(V02_MIGRATION_TARGETS)
        historical_apps = executor.loader.project_state(V02_MIGRATION_TARGETS).apps
        User = historical_apps.get_model("accounts", "User")
        Target = historical_apps.get_model("targets", "Target")
        Credential = historical_apps.get_model("vault", "Credential")
        PersonalVaultItem = historical_apps.get_model("vault", "PersonalVaultItem")
        AuditChainState = historical_apps.get_model("audit", "AuditChainState")

        AuditChainState.objects.update_or_create(
            pk=1,
            defaults={"last_sequence": 0, "last_hash": ""},
        )

        user = User.objects.create(
            username="v02-upgrade-witness",
            email="v02-upgrade@example.test",
            password="unusable-historical-hash",
        )
        target = Target.objects.create(
            name="v02-upgrade-target",
            hostname="192.0.2.20",
            port=22,
            protocol="ssh",
            labels={"upgrade": "witness"},
        )
        legacy_cipher = Fernet(LEGACY_KEY.encode())
        credential = Credential.objects.create(
            name="v02-upgrade-credential",
            target=target,
            username="upgrade-user",
            kind="password",
            encrypted_secret=legacy_cipher.encrypt(b"upgrade-secret"),
            secret_encryption_key_id="legacy",
        )
        item = PersonalVaultItem.objects.create(
            owner=user,
            name="v02-upgrade-vault-item",
            item_type="login",
            encrypted_payload=legacy_cipher.encrypt(
                json.dumps({"username": "historic", "password": "preserved"}).encode()
            ),
            encryption_key_id="legacy",
        )
        witness = {
            "user": user.pk,
            "target": target.pk,
            "credential": credential.pk,
            "item": item.pk,
        }

        executor = MigrationExecutor(connection)
        executor.migrate(latest_targets)

        monkeypatch.setenv("PAMOLIVE_VAULT_KEY", LEGACY_KEY)
        monkeypatch.setenv(
            "PAMOLIVE_AUDIT_SIGNING_KEY",
            "v02-upgrade-audit-signing-key-with-at-least-32-characters",
        )
        call_command(
            "migrate_secrets_to_keyring",
            "--apply",
            "--confirm",
            "MIGRATE-TO-KEYRING",
            verbosity=0,
        )

        from pamolive.accounts.models import User as CurrentUser
        from pamolive.targets.models import Target as CurrentTarget
        from pamolive.vault.models import Credential as CurrentCredential
        from pamolive.vault.models import PersonalVaultItem as CurrentPersonalVaultItem
        from pamolive.vault.services import VaultCipher

        assert CurrentUser.objects.filter(pk=witness["user"], username=user.username).exists()
        assert CurrentTarget.objects.filter(
            pk=witness["target"],
            hostname="192.0.2.20",
            labels={"upgrade": "witness"},
        ).exists()
        upgraded_credential = CurrentCredential.objects.get(pk=witness["credential"])
        assert upgraded_credential.secret_encryption_key_id == "keyring-v1"
        assert VaultCipher().decrypt(upgraded_credential.encrypted_secret) == "upgrade-secret"
        upgraded_item = CurrentPersonalVaultItem.objects.get(pk=witness["item"])
        assert upgraded_item.encryption_key_id == "keyring-v1"
        assert VaultCipher().decrypt_payload(upgraded_item.encrypted_payload) == {
            "username": "historic",
            "password": "preserved",
        }
    finally:
        MigrationExecutor(connection).migrate(latest_targets)

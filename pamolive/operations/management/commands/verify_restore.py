from django.contrib.auth import get_user_model
from django.core.management import BaseCommand, CommandError
from django.db import connection
from django.db.migrations.executor import MigrationExecutor

from pamolive.audit.services import verify_audit_chain
from pamolive.vault.key_rotation import rotate_vault_encryption


class Command(BaseCommand):
    help = "Vérifie en lecture seule une base restaurée PAM-olive."

    def add_arguments(self, parser):
        parser.add_argument(
            "--expect-user",
            default="",
            help="Nom d'utilisateur marqueur qui doit exister dans la restauration.",
        )

    def handle(self, *args, **options):
        executor = MigrationExecutor(connection)
        pending = executor.migration_plan(executor.loader.graph.leaf_nodes())
        if pending:
            raise CommandError(f"La restauration a {len(pending)} migration(s) en attente.")

        expected_user = options["expect_user"]
        if expected_user and not get_user_model().objects.filter(username=expected_user).exists():
            raise CommandError("L'utilisateur marqueur attendu est absent de la restauration.")

        audit = verify_audit_chain()
        if not audit.valid:
            raise CommandError(
                f"La chaîne d'audit restaurée est invalide ({len(audit.issues)} anomalie(s))."
            )

        vault = rotate_vault_encryption(apply=False)
        self.stdout.write(
            self.style.SUCCESS(
                "Restauration valide : "
                f"audit={audit.checked_events}, "
                f"champs_chiffrés={vault.scanned_fields}, "
                f"clé_active={vault.active_key_id}, "
                "migrations=0."
            )
        )

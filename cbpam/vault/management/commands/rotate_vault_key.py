from django.core.management.base import BaseCommand, CommandError

from cbpam.vault.key_rotation import rotate_vault_encryption
from cbpam.vault.services import VaultCipher


class Command(BaseCommand):
    help = "Validate or re-encrypt vault data with the configured active key."

    def add_arguments(self, parser):
        parser.add_argument(
            "--apply",
            action="store_true",
            help="Persist the re-encryption. Without this option the command is read-only.",
        )
        parser.add_argument(
            "--confirm-active-key-id",
            default="",
            help="Required with --apply; must exactly match CBPAM_VAULT_ACTIVE_KEY_ID.",
        )

    def handle(self, *args, **options):
        active_key_id = VaultCipher().active_key_id
        if options["apply"] and options["confirm_active_key_id"] != active_key_id:
            raise CommandError(
                "Refusing to write: --confirm-active-key-id must match "
                f"the active key identifier {active_key_id!r}."
            )
        report = rotate_vault_encryption(apply=options["apply"])
        mode = "APPLIED" if report.applied else "DRY RUN"
        self.stdout.write(
            f"{mode}: active={report.active_key_id} scanned={report.scanned_fields} "
            f"pending={report.fields_to_reencrypt} changed={report.reencrypted_fields}"
        )
        if not report.applied and report.fields_to_reencrypt:
            self.stdout.write(
                "No data was changed. Re-run with --apply and the confirmation option after backup."
            )

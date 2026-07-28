import json

from django.core.cache import cache
from django.core.management.base import BaseCommand
from django.db import connection
from django.db.migrations.executor import MigrationExecutor

from pamolive.licensing.services import cluster_enabled, get_license_status, node_id


class Command(BaseCommand):
    help = "Print installation and upgrade preflight status as JSON."

    def handle(self, *args, **options):
        database_ok = False
        cache_ok = False
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            database_ok = cursor.fetchone()[0] == 1

        probe_key = "pam-olive:preflight:cache"
        cache.set(probe_key, "ok", timeout=5)
        cache_ok = cache.get(probe_key) == "ok"
        cache.delete(probe_key)

        executor = MigrationExecutor(connection)
        pending_migrations = [
            f"{migration.app_label}.{migration.name}"
            for migration in executor.migration_plan(executor.loader.graph.leaf_nodes())
        ]
        license_status = get_license_status()
        self.stdout.write(
            json.dumps(
                {
                    "status": "ok"
                    if database_ok and cache_ok and not pending_migrations
                    else "attention_required",
                    "database_ok": database_ok,
                    "cache_ok": cache_ok,
                    "pending_migrations": pending_migrations,
                    "license": {
                        "edition": license_status.edition,
                        "valid": license_status.valid,
                        "source": license_status.source,
                        "reason": license_status.reason,
                        "cluster_allowed": license_status.cluster_allowed,
                    },
                    "cluster_enabled": cluster_enabled(),
                    "node_id": node_id(),
                },
                ensure_ascii=False,
                indent=2,
            )
        )

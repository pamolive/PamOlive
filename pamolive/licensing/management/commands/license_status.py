import json

from django.core.management.base import BaseCommand

from pamolive.licensing.services import cluster_enabled, get_license_status, node_id


class Command(BaseCommand):
    help = "Display the active PAM-olive edition and license status."

    def handle(self, *args, **options):
        payload = get_license_status().as_dict()
        payload["cluster_enabled"] = cluster_enabled()
        payload["node_id"] = node_id()
        self.stdout.write(json.dumps(payload, indent=2, sort_keys=True))

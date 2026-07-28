from django.core.checks import Error, Warning, register

from .exceptions import LicenseError
from .limits import assert_cluster_allowed
from .services import Edition, cluster_enabled, configured_edition, get_license_status, node_id


@register()
def licensing_checks(app_configs, **kwargs):
    messages = []
    edition = configured_edition()
    status = get_license_status()

    if edition not in Edition.CHOICES:
        messages.append(
            Error(
                "PAMOLIVE_EDITION is invalid.",
                hint="Use community, lab, business, or enterprise.",
                id="pamolive.E001",
            )
        )

    if not node_id():
        messages.append(
            Error(
                "PAMOLIVE_NODE_ID cannot be empty.",
                hint="Set PAMOLIVE_NODE_ID to a stable node name, for example vm-1.",
                id="pamolive.E002",
            )
        )

    try:
        assert_cluster_allowed()
    except LicenseError as exc:
        messages.append(
            Error(
                str(exc),
                hint="Disable PAMOLIVE_CLUSTER_ENABLED or switch to Lab/Business/Enterprise.",
                id="pamolive.E003",
            )
        )

    if edition in (Edition.BUSINESS, Edition.ENTERPRISE) and not status.valid:
        messages.append(
            Error(
                "The configured commercial license is not valid.",
                hint=status.reason or "Provide a valid signed license file.",
                id="pamolive.E004",
            )
        )

    if edition == Edition.LAB and cluster_enabled():
        messages.append(
            Warning(
                "PAM-olive Lab cluster mode is enabled.",
                hint="Lab is for evaluation only and is limited to 5 users and 2 targets.",
                id="pamolive.W001",
            )
        )

    return messages


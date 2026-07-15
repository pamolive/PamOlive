import json
import time
import urllib.error
import urllib.request

from django.conf import settings

from cbpam.gateway.crypto import request_signature


def notify_gateway_termination(session_id, timeout=2):
    body = json.dumps(
        {"session_id": str(session_id)},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    timestamp = str(int(time.time()))
    request = urllib.request.Request(
        f"{settings.CBPAM_GATEWAY_CONTROL_URL.rstrip('/')}/internal/control/terminate/",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-PAM-Timestamp": timestamp,
            "X-PAM-Signature": request_signature(
                settings.CBPAM_GATEWAY_SHARED_KEY,
                timestamp,
                body,
            ),
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status == 202
    except (urllib.error.URLError, TimeoutError):
        return False

import json
import time
import urllib.error
import urllib.request
import uuid

from django.conf import settings

from pamolive.gateway.crypto import request_signature


def notify_gateway_termination(session_id, timeout=2):
    body = json.dumps(
        {"session_id": str(session_id)},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    timestamp = str(int(time.time()))
    request_id = str(uuid.uuid4())
    path = "/internal/control/terminate/"
    request = urllib.request.Request(
        f"{settings.PAMOLIVE_GATEWAY_CONTROL_URL.rstrip('/')}{path}",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-PAM-Timestamp": timestamp,
            "X-PAM-Request-ID": request_id,
            "X-PAM-Signature-Version": "2",
            "X-PAM-Signature": request_signature(
                settings.PAMOLIVE_GATEWAY_SHARED_KEY,
                timestamp,
                body,
                method="POST",
                path=path,
                request_id=request_id,
            ),
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status == 202
    except (urllib.error.URLError, TimeoutError):
        return False

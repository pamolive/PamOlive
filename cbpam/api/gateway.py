import json
import re

from django.conf import settings
from django.core.exceptions import PermissionDenied, ValidationError
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from cbpam.audit.services import record_event
from cbpam.common.network import request_client_ip
from cbpam.gateway.crypto import encrypt_envelope, verify_request_signature
from cbpam.sessions.models import PrivilegedSession
from cbpam.sessions.services import close_session, consume_session_ticket
from cbpam.vault.leases import consume_secret_lease, issue_secret_lease
from cbpam.vault.models import SecretLease


def _authenticated_payload(request):
    timestamp = request.headers.get("X-PAM-Timestamp", "")
    signature = request.headers.get("X-PAM-Signature", "")
    if not verify_request_signature(
        settings.CBPAM_GATEWAY_SHARED_KEY,
        timestamp,
        request.body,
        signature,
    ):
        raise PermissionDenied("Authentification interne refusée.")
    try:
        payload = json.loads(request.body)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValidationError("Corps JSON invalide.") from error
    if not isinstance(payload, dict):
        raise ValidationError("Corps JSON invalide.")
    return payload


@csrf_exempt
@require_POST
def gateway_authorize(request):
    session = None
    try:
        payload = _authenticated_payload(request)
        source_ip = payload.get("source_ip") or request_client_ip(request)
        session = consume_session_ticket(
            session_id=payload.get("session_id"),
            token=payload.get("ticket", ""),
            user=get_object_or_404(PrivilegedSession, pk=payload.get("session_id")).user,
            source_ip=source_ip,
        )
        credential = session.credential
        if credential is None:
            raise PermissionDenied("Aucun identifiant n’est lié à cette session.")
        lease, secret_token = issue_secret_lease(
            user=session.user,
            credential=credential,
            purpose=SecretLease.Purpose.SESSION,
            lifetime_seconds=30,
            source_ip=source_ip,
        )
        _consumed, secret = consume_secret_lease(
            token=secret_token,
            expected_user=session.user,
            expected_purpose=SecretLease.Purpose.SESSION,
        )
        envelope_data = {
            "session_id": str(session.pk),
            "pam_user_id": str(session.user_id),
            "protocol": session.target.protocol,
            "host": session.target.hostname,
            "port": session.target.port,
            "username": credential.username,
            "credential_kind": credential.kind,
            "secret": secret,
            "expires_at": session.expires_at.isoformat() if session.expires_at else None,
            "lease_id": str(lease.pk),
        }
        if session.target.protocol == session.target.Protocol.SSH:
            host_pattern = (
                session.target.hostname
                if session.target.port == 22
                else f"[{session.target.hostname}]:{session.target.port}"
            )
            host_keys = session.target.host_keys.filter(revoked_at__isnull=True)
            known_hosts = "".join(f"{host_pattern} {key.public_key}\n" for key in host_keys)
            if not known_hosts:
                raise PermissionDenied("Aucune clé d’hôte active n’est disponible.")
            envelope_data["known_hosts"] = known_hosts
        elif session.target.protocol == session.target.Protocol.RDP:
            if credential.kind != credential.Kind.PASSWORD:
                raise PermissionDenied("RDP requiert un identifiant de type mot de passe.")
            domain = credential.domain
            envelope_data.update(
                {
                    "domain": (domain.dns_name or domain.name) if domain else "",
                    "rdp_security": session.target.rdp_security,
                    "rdp_certificate_fingerprints": (
                        session.target.rdp_certificate_fingerprints
                    ),
                    "rdp_server_layout": session.target.rdp_server_layout,
                    "rdp_resize_method": session.target.rdp_resize_method,
                    "allow_clipboard_copy": session.policy.allow_clipboard_copy,
                    "allow_clipboard_paste": session.policy.allow_clipboard_paste,
                }
            )
        else:
            raise PermissionDenied("Le protocole de session n'est pas pris en charge.")
        envelope = encrypt_envelope(envelope_data, settings.CBPAM_GATEWAY_SHARED_KEY)
    except (PermissionDenied, ValidationError, ValueError):
        if session is not None:
            close_session(session, reason="gateway_authorization_failed", failed=True)
        return JsonResponse({"detail": "Autorisation du broker refusée."}, status=403)
    response = JsonResponse({"envelope": envelope})
    response["Cache-Control"] = "private, no-store, must-revalidate"
    return response


@csrf_exempt
@require_POST
def gateway_close(request):
    try:
        payload = _authenticated_payload(request)
        session = get_object_or_404(PrivilegedSession, pk=payload.get("session_id"))
        recording_reference = str(payload.get("recording_reference", ""))[:500]
        if recording_reference:
            if not re.fullmatch(r"[0-9a-fA-F-]{36}\.pamrec", recording_reference):
                raise ValidationError("Référence d’enregistrement invalide.")
            session.recording_reference = recording_reference
            session.save(update_fields=("recording_reference", "updated_at"))
            recording_sha256 = str(payload.get("recording_sha256", ""))
            if not re.fullmatch(r"[0-9a-f]{64}", recording_sha256):
                raise ValidationError("Empreinte d’enregistrement invalide.")
            record_event(
                actor=None,
                action="session.recording_sealed",
                resource=session,
                metadata={
                    "sha256": recording_sha256,
                    "bytes_in": max(0, int(payload.get("bytes_in", 0))),
                    "bytes_out": max(0, int(payload.get("bytes_out", 0))),
                },
                source_ip=request_client_ip(request),
            )
        close_session(
            session,
            reason=str(payload.get("reason", "gateway_closed"))[:255],
            failed=payload.get("outcome") == "failed",
        )
    except (PermissionDenied, ValidationError, ValueError):
        return JsonResponse({"detail": "Rapport du broker refusé."}, status=403)
    return JsonResponse({"status": "recorded"})

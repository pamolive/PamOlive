import ipaddress

from django.conf import settings


def _valid_ip(value):
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def request_client_ip(request):
    if settings.PAMOLIVE_TRUST_PROXY_HEADERS:
        forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
        if forwarded:
            candidate = _valid_ip(forwarded.split(",", 1)[0].strip())
            if candidate:
                return candidate
    return _valid_ip(request.META.get("REMOTE_ADDR", ""))

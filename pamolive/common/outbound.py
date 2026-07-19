import ipaddress
import socket
from urllib.parse import urlparse

from django.conf import settings
from django.core.exceptions import ValidationError


def _allowed_networks():
    networks = []
    for value in settings.PAMOLIVE_OUTBOUND_ALLOWED_CIDRS:
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError as error:
            raise ValidationError(f"CIDR sortant invalide : {value}.") from error
    return networks


def validate_outbound_host(hostname, *, port):
    """Reject special-use destinations unless an operator explicitly allowlists them."""

    try:
        addresses = {
            item[4][0] for item in socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        }
    except socket.gaierror as error:
        if settings.PAMOLIVE_OUTBOUND_ALLOW_UNRESOLVED_HOSTS:
            return
        raise ValidationError("La destination sortante ne peut pas être résolue.") from error
    allowed = _allowed_networks()
    for value in addresses:
        address = ipaddress.ip_address(value)
        if any(address in network for network in allowed):
            continue
        if not address.is_global:
            raise ValidationError(
                "La destination sortante utilise une adresse spéciale ou privée non autorisée."
            )


def validate_outbound_url(value, *, schemes=("https",)):
    parsed = urlparse(value)
    if parsed.scheme not in schemes or not parsed.hostname or parsed.username or parsed.password:
        raise ValidationError("L’URL sortante est invalide ou utilise un protocole non autorisé.")
    default_port = 443 if parsed.scheme == "https" else 80
    validate_outbound_host(parsed.hostname, port=parsed.port or default_port)
    return value

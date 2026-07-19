from urllib.parse import urljoin

from django.conf import settings


def public_absolute_uri(request, path):
    if settings.PAMOLIVE_PUBLIC_URL:
        return urljoin(f"{settings.PAMOLIVE_PUBLIC_URL}/", path.lstrip("/"))
    return request.build_absolute_uri(path)

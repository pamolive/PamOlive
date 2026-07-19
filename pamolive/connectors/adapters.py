import ssl
from dataclasses import dataclass, field
from urllib.parse import urlparse

from ldap3 import (
    AUTO_BIND_NO_TLS,
    AUTO_BIND_TLS_BEFORE_BIND,
    NONE,
    Connection,
    Server,
    Tls,
)

from pamolive.common.outbound import validate_outbound_host

from .models import IdentitySource
from .services import get_identity_source_configuration


class DirectoryConnectionError(RuntimeError):
    pass


@dataclass(frozen=True)
class DirectoryUser:
    subject: str
    username: str
    email: str = ""
    display_name: str = ""
    groups: tuple[str, ...] = ()
    claims: dict = field(default_factory=dict)


class LDAPDirectoryAdapter:
    def __init__(self, source):
        if source.kind not in {
            IdentitySource.Kind.LDAP,
            IdentitySource.Kind.ACTIVE_DIRECTORY,
        }:
            raise ValueError("Cette source n’est pas compatible avec l’adaptateur LDAP.")
        self.source = source
        self.configuration = get_identity_source_configuration(source)

    def _connection(self):
        configuration = self.configuration
        parsed = urlparse(configuration["server_uri"])
        use_ssl = parsed.scheme == "ldaps"
        validate_outbound_host(parsed.hostname, port=parsed.port or (636 if use_ssl else 389))
        tls = Tls(validate=ssl.CERT_REQUIRED)
        server = Server(
            parsed.hostname,
            port=parsed.port or (636 if use_ssl else 389),
            use_ssl=use_ssl,
            tls=tls,
            get_info=NONE,
            connect_timeout=int(configuration.get("connect_timeout_seconds", 10)),
        )
        auto_bind = (
            AUTO_BIND_TLS_BEFORE_BIND
            if configuration.get("use_start_tls") and not use_ssl
            else AUTO_BIND_NO_TLS
        )
        try:
            return Connection(
                server,
                user=configuration.get("bind_dn") or None,
                password=configuration.get("bind_password") or None,
                auto_bind=auto_bind,
                raise_exceptions=True,
            )
        except Exception as error:
            raise DirectoryConnectionError("Connexion à l’annuaire impossible.") from error

    def test_connection(self):
        connection = self._connection()
        connection.unbind()
        return True

    def fetch_users(self):
        configuration = self.configuration
        username_attribute = configuration.get("username_attribute", "uid")
        email_attribute = configuration.get("email_attribute", "mail")
        display_name_attribute = configuration.get("display_name_attribute", "displayName")
        group_attribute = configuration.get("group_attribute", "memberOf")
        attributes = [
            username_attribute,
            email_attribute,
            display_name_attribute,
            group_attribute,
        ]
        connection = self._connection()
        try:
            entries = connection.extend.standard.paged_search(
                search_base=configuration["base_dn"],
                search_filter=configuration["user_filter"],
                attributes=attributes,
                paged_size=500,
                generator=True,
            )
            users = []
            for entry in entries:
                if entry.get("type") != "searchResEntry":
                    continue
                values = entry.get("attributes", {})
                username = values.get(username_attribute)
                if isinstance(username, list):
                    username = username[0] if username else ""
                if not username:
                    continue
                groups = values.get(group_attribute) or []
                if isinstance(groups, str):
                    groups = [groups]
                email = values.get(email_attribute) or ""
                display_name = values.get(display_name_attribute) or ""
                if isinstance(email, list):
                    email = email[0] if email else ""
                if isinstance(display_name, list):
                    display_name = display_name[0] if display_name else ""
                users.append(
                    DirectoryUser(
                        subject=entry["dn"],
                        username=str(username),
                        email=str(email),
                        display_name=str(display_name),
                        groups=tuple(str(group) for group in groups),
                        claims={"dn": entry["dn"]},
                    )
                )
            return users
        except Exception as error:
            raise DirectoryConnectionError("Lecture de l’annuaire impossible.") from error
        finally:
            connection.unbind()


def adapter_for(source):
    if source.kind in {IdentitySource.Kind.LDAP, IdentitySource.Kind.ACTIVE_DIRECTORY}:
        return LDAPDirectoryAdapter(source)
    raise ValueError("Cette source ne prend pas en charge la synchronisation d’annuaire.")

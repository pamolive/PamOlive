from dataclasses import dataclass

from .models import Role


@dataclass(frozen=True)
class PermissionLevel:
    value: str
    label: str
    capabilities: tuple[str, ...] = ()


@dataclass(frozen=True)
class PermissionArea:
    field_name: str
    section: str
    label: str
    help_text: str
    levels: tuple[PermissionLevel, ...]


NONE = PermissionLevel("none", "Aucun accès")


def _area(field_name, section, label, help_text, *levels):
    return PermissionArea(field_name, section, label, help_text, (NONE, *levels))


PERMISSION_AREAS = (
    _area(
        "users_level",
        "Identités et délégation",
        "Utilisateurs",
        "Consulter ou administrer les comptes locaux.",
        PermissionLevel("view", "Lecture", (Role.Capability.USERS_VIEW,)),
        PermissionLevel(
            "manage",
            "Gestion",
            (Role.Capability.USERS_VIEW, Role.Capability.USERS_MANAGE),
        ),
    ),
    _area(
        "groups_level",
        "Identités et délégation",
        "Groupes utilisateurs",
        "Consulter ou administrer les groupes et leurs membres.",
        PermissionLevel("view", "Lecture", (Role.Capability.GROUPS_VIEW,)),
        PermissionLevel(
            "manage",
            "Gestion",
            (Role.Capability.GROUPS_VIEW, Role.Capability.GROUPS_MANAGE),
        ),
    ),
    _area(
        "roles_level",
        "Identités et délégation",
        "Profils de permissions",
        "Déléguer uniquement des profils que l’opérateur est autorisé à gérer.",
        PermissionLevel("view", "Lecture", (Role.Capability.ROLES_VIEW,)),
        PermissionLevel(
            "manage",
            "Gestion",
            (Role.Capability.ROLES_VIEW, Role.Capability.ROLES_MANAGE),
        ),
    ),
    _area(
        "identity_sources_level",
        "Identités et délégation",
        "Annuaires et fournisseurs d’identité",
        "LDAP, Active Directory, OIDC et synchronisation des identités.",
        PermissionLevel(
            "view", "Lecture", (Role.Capability.IDENTITY_SOURCES_VIEW,)
        ),
        PermissionLevel(
            "manage",
            "Gestion",
            (
                Role.Capability.IDENTITY_SOURCES_VIEW,
                Role.Capability.IDENTITY_SOURCES_MANAGE,
            ),
        ),
        PermissionLevel(
            "operate",
            "Gestion et synchronisation",
            (
                Role.Capability.IDENTITY_SOURCES_VIEW,
                Role.Capability.IDENTITY_SOURCES_MANAGE,
                Role.Capability.IDENTITY_SOURCES_SYNC,
            ),
        ),
    ),
    _area(
        "targets_level",
        "Ressources privilégiées",
        "Équipements SSH / RDP",
        "Consulter ou administrer les équipements publiés.",
        PermissionLevel("view", "Lecture", (Role.Capability.TARGETS_VIEW,)),
        PermissionLevel(
            "manage",
            "Gestion",
            (Role.Capability.TARGETS_VIEW, Role.Capability.TARGETS_MANAGE),
        ),
    ),
    _area(
        "target_groups_level",
        "Ressources privilégiées",
        "Groupes de cibles",
        "Consulter ou administrer les périmètres de ressources.",
        PermissionLevel(
            "view", "Lecture", (Role.Capability.TARGET_GROUPS_VIEW,)
        ),
        PermissionLevel(
            "manage",
            "Gestion",
            (
                Role.Capability.TARGET_GROUPS_VIEW,
                Role.Capability.TARGET_GROUPS_MANAGE,
            ),
        ),
    ),
    _area(
        "domains_level",
        "Ressources privilégiées",
        "Domaines",
        "Consulter ou administrer les domaines de comptes.",
        PermissionLevel("view", "Lecture", (Role.Capability.DOMAINS_VIEW,)),
        PermissionLevel(
            "manage",
            "Gestion",
            (Role.Capability.DOMAINS_VIEW, Role.Capability.DOMAINS_MANAGE),
        ),
    ),
    _area(
        "credentials_level",
        "Secrets et autorisations",
        "Comptes privilégiés",
        "Administrer les métadonnées sans révéler automatiquement les secrets.",
        PermissionLevel(
            "view", "Lecture des métadonnées", (Role.Capability.CREDENTIALS_VIEW_METADATA,)
        ),
        PermissionLevel(
            "manage",
            "Gestion des comptes",
            (
                Role.Capability.CREDENTIALS_VIEW_METADATA,
                Role.Capability.CREDENTIALS_MANAGE,
            ),
        ),
    ),
    _area(
        "secret_operations_level",
        "Secrets et autorisations",
        "Opérations sensibles sur les secrets",
        "La révélation et la rotation restent séparées de la gestion des comptes.",
        PermissionLevel(
            "reveal",
            "Révélation autorisée",
            (
                Role.Capability.CREDENTIALS_VIEW_METADATA,
                Role.Capability.CREDENTIALS_REVEAL,
            ),
        ),
        PermissionLevel(
            "rotate",
            "Rotation autorisée",
            (
                Role.Capability.CREDENTIALS_VIEW_METADATA,
                Role.Capability.CREDENTIALS_ROTATE,
            ),
        ),
        PermissionLevel(
            "full",
            "Révélation et rotation",
            (
                Role.Capability.CREDENTIALS_VIEW_METADATA,
                Role.Capability.CREDENTIALS_REVEAL,
                Role.Capability.CREDENTIALS_ROTATE,
            ),
        ),
    ),
    _area(
        "policies_level",
        "Secrets et autorisations",
        "Autorisations d’accès",
        "Relier groupes utilisateurs, groupes de cibles et conditions d’accès.",
        PermissionLevel("view", "Lecture", (Role.Capability.POLICIES_VIEW,)),
        PermissionLevel(
            "manage",
            "Gestion",
            (Role.Capability.POLICIES_VIEW, Role.Capability.POLICIES_MANAGE),
        ),
    ),
    _area(
        "approvals_level",
        "Exploitation et contrôle",
        "Approbations",
        "La décision inclut la consultation des demandes concernées.",
        PermissionLevel("view", "Lecture", (Role.Capability.APPROVALS_VIEW,)),
        PermissionLevel(
            "decide",
            "Décision",
            (Role.Capability.APPROVALS_VIEW, Role.Capability.APPROVALS_DECIDE),
        ),
    ),
    _area(
        "sessions_level",
        "Exploitation et contrôle",
        "Sessions privilégiées",
        "Superviser, rejoindre ou interrompre les sessions actives.",
        PermissionLevel("view", "Lecture", (Role.Capability.SESSIONS_VIEW,)),
        PermissionLevel(
            "control",
            "Supervision et terminaison",
            (
                Role.Capability.SESSIONS_VIEW,
                Role.Capability.SESSIONS_JOIN,
                Role.Capability.SESSIONS_TERMINATE,
            ),
        ),
    ),
    _area(
        "audit_level",
        "Exploitation et contrôle",
        "Audit",
        "Consulter la piste d’audit ou exporter une preuve vérifiée.",
        PermissionLevel("view", "Lecture", (Role.Capability.AUDIT_VIEW,)),
        PermissionLevel(
            "export",
            "Lecture et export",
            (Role.Capability.AUDIT_VIEW, Role.Capability.AUDIT_EXPORT),
        ),
    ),
    _area(
        "system_level",
        "Exploitation et contrôle",
        "Configuration système",
        "État de santé, sécurité de la plateforme et intégrations.",
        PermissionLevel("view", "Lecture", (Role.Capability.SYSTEM_VIEW,)),
        PermissionLevel(
            "manage",
            "Gestion",
            (Role.Capability.SYSTEM_VIEW, Role.Capability.SYSTEM_MANAGE),
        ),
    ),
)


def level_for_capabilities(area, capabilities):
    granted = set(capabilities or ())
    selected = "none"
    for level in area.levels:
        if level.capabilities and set(level.capabilities).issubset(granted):
            selected = level.value
    return selected


def capabilities_from_levels(values):
    capabilities = set()
    for area in PERMISSION_AREAS:
        selected = values.get(area.field_name, "none")
        level = next((item for item in area.levels if item.value == selected), NONE)
        capabilities.update(level.capabilities)
    if capabilities:
        capabilities.add(Role.Capability.CONSOLE_ACCESS)
        capabilities.add(Role.Capability.CONFIGURATION_VIEW)
    return sorted(capabilities)


def normalize_capabilities(capabilities):
    granted = set(capabilities or ())
    dependencies = {
        Role.Capability.USERS_MANAGE: Role.Capability.USERS_VIEW,
        Role.Capability.GROUPS_MANAGE: Role.Capability.GROUPS_VIEW,
        Role.Capability.ROLES_MANAGE: Role.Capability.ROLES_VIEW,
        Role.Capability.IDENTITY_SOURCES_MANAGE: Role.Capability.IDENTITY_SOURCES_VIEW,
        Role.Capability.IDENTITY_SOURCES_SYNC: Role.Capability.IDENTITY_SOURCES_VIEW,
        Role.Capability.TARGETS_MANAGE: Role.Capability.TARGETS_VIEW,
        Role.Capability.TARGET_GROUPS_MANAGE: Role.Capability.TARGET_GROUPS_VIEW,
        Role.Capability.DOMAINS_MANAGE: Role.Capability.DOMAINS_VIEW,
        Role.Capability.CREDENTIALS_MANAGE: Role.Capability.CREDENTIALS_VIEW_METADATA,
        Role.Capability.CREDENTIALS_REVEAL: Role.Capability.CREDENTIALS_VIEW_METADATA,
        Role.Capability.CREDENTIALS_ROTATE: Role.Capability.CREDENTIALS_VIEW_METADATA,
        Role.Capability.POLICIES_MANAGE: Role.Capability.POLICIES_VIEW,
        Role.Capability.APPROVALS_DECIDE: Role.Capability.APPROVALS_VIEW,
        Role.Capability.AUDIT_EXPORT: Role.Capability.AUDIT_VIEW,
        Role.Capability.SESSIONS_TERMINATE: Role.Capability.SESSIONS_VIEW,
        Role.Capability.SESSIONS_JOIN: Role.Capability.SESSIONS_VIEW,
        Role.Capability.SYSTEM_MANAGE: Role.Capability.SYSTEM_VIEW,
    }
    for capability, dependency in dependencies.items():
        if capability in granted:
            granted.add(dependency)
    if granted:
        granted.add(Role.Capability.CONSOLE_ACCESS)
        granted.add(Role.Capability.CONFIGURATION_VIEW)
    return sorted(granted)


def permission_summary(capabilities):
    summaries = []
    for area in PERMISSION_AREAS:
        selected = level_for_capabilities(area, capabilities)
        if selected == "none":
            continue
        label = next(level.label for level in area.levels if level.value == selected)
        summaries.append(f"{area.label} · {label}")
    return summaries

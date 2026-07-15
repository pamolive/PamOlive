# Changelog

Toutes les modifications notables sont documentées ici. Le projet suit le
versionnage sémantique à partir de la future V1 ; les versions `0.x` peuvent encore
faire évoluer les interfaces et le schéma.

## [Unreleased]

### Added

- Sources d'identité LDAP, Active Directory et OIDC avec correspondance de groupes.
- Domaines, types de cibles et de comptes, et clés d'hôte SSH approuvées/révoquées.
- Contraintes de politique par identifiant, protocole, horaire, réseau et concurrence.
- Quorum d'approbation, groupes d'approbateurs et décisions immuables.
- Tickets de session et baux de secrets courts, liés à la source et à usage unique.
- Passerelle SSH isolée, terminal WebSocket et enregistrements chiffrés scellés.
- Journal d'audit v2 séquencé, signé, vérifiable et exportable en CSV/JSONL.
- Préparation GitHub : CI renforcée, CodeQL, Dependabot et pipeline de release GHCR.
- Rotation orchestrée des identifiants, contrôles de santé, métriques et sauvegardes vérifiables.
- Trousseau de clés du coffre avec rotation transactionnelle et commande sûre en deux étapes.
- Courtage RDP par Apache Guacamole 1.6.0 sur origine dédiée, ticket à usage unique et
  paramètres de sécurité/presse-papiers pilotés par les politiques.

### Fixed

- Déclaration explicite de `requests`, dépendance d'exécution requise par Authlib.
- Compatibilité Synology DSM des proxies Caddy par capacité `NET_BIND_SERVICE` minimale et
  réseau public dédié au seul point d'entrée RDP.

### Security

- Validation stricte des clés d'hôte SSH ; aucun mode permissif en production.
- API interne passerelle signée par HMAC et secrets transmis dans une enveloppe Fernet.
- Réseaux Docker séparés et passerelle sans accès direct à PostgreSQL.
- Politique CSP avec HTMX auto-hébergé et en-têtes de sécurité applicatifs/proxy.
- Arrêt distant audité des sessions et scellement de l'enregistrement associé.
- Authentification JSON Guacamole expirant après 15 secondes, jamais transmise dans une URL.
- `guacd` sans port hôte, réseaux RDP compartimentés et fonctions de redirection désactivées
  par défaut.

## [0.2.0] - 2026-07-13

### Added

- Product roles and granular capabilities for administrators, auditors and users.
- Multi-group membership with policies linking user groups to target groups.
- Personal encrypted vault entries for logins, TOTP seeds, payment cards and secure notes.
- Target credential vault with multiple local credentials and optional TOTP per target.
- Local account profile, password change and TOTP MFA enrollment.
- Product administration console for identities, target groups, credentials, policies,
  approvals, sessions and audit events.
- Hierarchical, collapsible administration navigation inspired by established PAM workflows.
- Tests for permission boundaries, MFA, personal vault ownership and approval separation.

### Security

- Technical Django administration is restricted to super administrators.
- Auditors receive read-only configuration and monitoring access without secret disclosure.
- Administrators cannot approve their own access requests.

## [0.1.0] - 2026-07-13

### Added

- Modular Django foundation for the CBPAM domains.
- PostgreSQL, Redis, Channels and Celery runtime.
- Encrypted credential service and append-only hash-chained audit events.
- Docker Compose, CI, tests and MkDocs documentation.

### Changed

- Product identity renamed from CBPAM to PAM-olive.
- Authentication and dashboard interfaces redesigned with an accessible responsive design system.

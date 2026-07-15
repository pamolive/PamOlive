# Matrice de permissions V1

## Principes

- Refus par défaut : l'absence de permission interdit l'action.
- Séparation lecture / modification / action sensible.
- Les droits reçus par plusieurs groupes sont réunis, mais une politique d'accès reste
  nécessaire pour atteindre une cible ou révéler un secret de cible.
- Le statut Django `is_superuser` est réservé au Super administrateur technique.
- Le rôle Administrateur PAM-olive ne donne jamais accès à `/django-admin/`.

## Profils système

| Domaine | Super admin | Administrateur | Auditeur | Approbateur | Utilisateur |
| --- | --- | --- | --- | --- | --- |
| Console produit | complet | complet | lecture | approbations | non |
| Utilisateurs / groupes | complet | gérer | lecture | non | soi-même |
| Profils de permissions | complet | gérer hors système | lecture | non | non |
| Sources LDAP/OIDC | complet | gérer / synchroniser | lecture | non | non |
| Cibles / domaines | complet | gérer | lecture | non | cibles autorisées |
| Métadonnées des comptes | complet | gérer | lecture sans secret | non | comptes autorisés |
| Révélation de secrets | selon politique | selon politique | jamais | jamais | selon politique |
| Politiques | complet | gérer | lecture | non | non |
| Approbations | complet | décider pour autrui | lecture | décider pour autrui | ses demandes |
| Sessions | complet | consulter / terminer | consulter | non | ses sessions |
| Audit | complet | consulter | consulter / exporter | limité | ses événements |
| Administration Django | oui | non | non | non | non |

## Familles de capacités

Les capacités techniques utilisent une notation stable `ressource.action` :

- `users.view`, `users.manage`
- `groups.view`, `groups.manage`
- `roles.view`, `roles.manage`
- `identity_sources.view`, `identity_sources.manage`, `identity_sources.sync`
- `targets.view`, `targets.manage`
- `target_groups.view`, `target_groups.manage`
- `domains.view`, `domains.manage`
- `credentials.view_metadata`, `credentials.manage`, `credentials.reveal`,
  `credentials.rotate`
- `policies.view`, `policies.manage`
- `approvals.view`, `approvals.decide`
- `sessions.view`, `sessions.terminate`, `sessions.join`
- `audit.view`, `audit.export`
- `system.view`, `system.manage`

Les profils système sont fournis par migration et ne peuvent pas être supprimés. Leur contenu
peut évoluer par migration versionnée afin que les montées de version restent reproductibles.

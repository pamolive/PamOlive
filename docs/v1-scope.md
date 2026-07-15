# Périmètre de PAM-olive V1

## Vision

PAM-olive V1 est un bastion open source destiné à gouverner, délivrer et tracer les accès
privilégiés. Son architecture s'inspire des concepts éprouvés des produits PAM du marché,
notamment la séparation des identités, des ressources, des autorisations, des approbations,
des sessions et de l'audit. Le produit, son code et son identité restent propres à PAM-olive.

## Critères obligatoires de sortie

Une version ne peut être déclarée « candidate V1 » que si tous les critères suivants sont
satisfaits :

1. Les rôles Super administrateur, Administrateur, Auditeur, Approbateur et Utilisateur sont
   appliqués côté serveur avec des permissions de lecture et de modification distinctes.
2. Un utilisateur peut appartenir à plusieurs groupes et recevoir l'union contrôlée de leurs
   autorisations actives.
3. Les identités locales, LDAP/Active Directory et OpenID Connect sont modélisées, testables et
   synchronisables sans conserver de mot de passe d'annuaire en clair.
4. Les équipements, applications, domaines, groupes de cibles et comptes privilégiés sont
   représentés séparément.
5. Les secrets sont chiffrés au repos, versionnés, révélés uniquement après autorisation et
   chaque consultation est auditée.
6. Les politiques relient explicitement groupes d'utilisateurs, groupes de cibles, comptes,
   protocoles, plages horaires, MFA et workflow d'approbation.
7. Un approbateur ne peut jamais approuver sa propre demande. Les décisions, motifs et durées
   sont immuables dans l'historique d'audit.
8. Le courtage SSH est isolé du processus web, vérifie une autorisation à durée limitée et
   produit une trace de session. Le lancement RDP fournit au minimum un flux gouverné et une
   stratégie de traçabilité documentée.
9. L'auditeur peut consulter et exporter les événements et sessions sans révéler de secret ni
   modifier la configuration.
10. La restauration, la rotation des clés, les contrôles de santé, les métriques et les alertes
    d'exploitation sont documentés et testés.
11. Les migrations sont additives, les tests automatisés couvrent au moins 90 % du cœur métier
    et les contrôles de sécurité Django ne produisent aucune erreur bloquante.
12. Une installation neuve et une mise à niveau depuis la v0.2 sont toutes deux reproductibles
    avec Docker Compose sans perte de données.

## Domaines fonctionnels V1

- Identités : comptes locaux, identités externes, MFA, préférences et cycle de vie.
- RBAC : profils de permissions, groupes, délégations temporaires et limitations.
- Référentiel : équipements, applications, domaines, groupes et comptes de cibles.
- Coffres : coffre personnel, coffre des cibles, TOTP, clés SSH et métadonnées de rotation.
- Autorisations : règles d'accès, protocoles, actions, MFA, horaires et approbations.
- Approbations : demandes, quorum, décisions, expiration et historique.
- Sessions : préparation, lancement, surveillance, fermeture et enregistrement.
- Audit : chaîne d'intégrité, filtres, exports, alertes et intégration SIEM.
- Connecteurs : LDAP/AD, OIDC, SMTP, SIEM et coffres externes par interfaces extensibles.
- API : endpoints versionnés, jetons de service limités et documentation OpenAPI.

## Hors périmètre initial

- Reproduction à l'identique d'une interface ou d'un code propriétaire.
- Découverte réseau intrusive activée par défaut.
- Rotation automatique sur tous les systèmes d'exploitation sans plugin validé.
- Haute disponibilité multi-site avant validation de la V1 mono-site.

## Règle de sécurité du NAS de développement

Le NAS de référence contient des données critiques hors PAM-olive. Aucune opération de
suppression, de réinitialisation ou de modification de données, volumes, conteneurs ou comptes
du NAS n'est autorisée pendant la construction locale de la V1. Un futur déploiement nécessitera
une autorisation explicite, une sauvegarde vérifiée et un plan de retour arrière non destructif.

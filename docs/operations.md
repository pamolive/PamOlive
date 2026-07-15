# Exploitation

Cette page décrit les contrôles disponibles pendant la phase pré‑V1. Les opérations de
restauration restent interdites sur le NAS de référence tant qu'un exercice isolé et un plan
de retour arrière n'ont pas été approuvés.

## Santé

| Endpoint | Authentification | Usage |
| --- | --- | --- |
| `/api/health/live/` | aucune | processus web vivant, sans dépendance |
| `/api/health/ready/` | aucune | PostgreSQL et cache accessibles |
| `/api/health/integrity/` | jeton Bearer d'exploitation | chaîne d'audit entièrement valide |
| `/api/metrics/` | jeton Bearer d'exploitation | métriques agrégées au format Prometheus |

Le jeton est `CBPAM_OPERATIONS_TOKEN`. Il doit être différent de toutes les clés de coffre,
d'audit, de passerelle et d'enregistrement. Il n'est jamais transmis à la passerelle SSH.

Alertes minimales recommandées :

- readiness en échec pendant plus de deux minutes ;
- intégrité d'audit en échec, même une seule fois ;
- `pam_olive_rotation_jobs_failed` ou `pam_olive_rotation_jobs_action_required` en hausse ;
- session restant dans l'état `terminating` ;
- volume PostgreSQL ou enregistrements dépassant 80 % de sa capacité.

## Rotation des identifiants de cibles

Une rotation possède un job immuable et un fournisseur nommé. Le fournisseur est chargé via
`CBPAM_ROTATION_BACKENDS`, par exemple :

```env
CBPAM_ROTATION_BACKENDS={"linux":"my_plugin.backends.LinuxPasswordBackend"}
```

Le fournisseur reçoit l'identifiant, l'ancien secret et un nouveau secret généré. PAM-olive
chiffre le candidat avant l'appel distant, ne promeut le nouveau secret qu'après succès,
incrémente sa version et audite le résultat. Une exception inattendue est expurgée. Sans
fournisseur explicite, le job passe en « action requise » et aucun réseau n'est contacté.

La tâche périodique Celery recherche les rotations dues toutes les cinq minutes. Un seul job
actif est permis par identifiant.

## Rotation de la clé maîtresse du coffre

Le trousseau est défini par `CBPAM_VAULT_KEYS` et la clé d'écriture par
`CBPAM_VAULT_ACTIVE_KEY_ID`. `CBPAM_VAULT_KEY` reste l'entrée compatible identifiée
`legacy`. Exemple de transition :

```env
CBPAM_VAULT_KEY=<ancienne-cle-conservee-temporairement>
CBPAM_VAULT_KEYS={"v2":"<nouvelle-cle-fernet>"}
CBPAM_VAULT_ACTIVE_KEY_ID=v2
```

Après une sauvegarde vérifiée, exécuter d'abord le contrôle en lecture seule :

```sh
docker compose exec web python manage.py rotate_vault_key
```

Puis seulement si chaque champ est déchiffrable :

```sh
docker compose exec web python manage.py rotate_vault_key \
  --apply --confirm-active-key-id v2
```

La commande traite les identifiants, TOTP, coffres personnels, configurations de connecteurs,
MFA et secrets candidats de rotation dans une transaction. Elle n'incrémente pas la version
métier du mot de passe. Conserver l'ancienne clé jusqu'à une nouvelle sauvegarde, un nouveau
dry-run indiquant `pending=0` et un exercice de restauration réussi.

## Sauvegarde

Depuis le répertoire du projet sur une machine Docker :

```sh
sh scripts/backup.sh /chemin/hors-du-projet/pam-olive-YYYYMMDD-HHMM
```

Le script :

1. refuse un chemin existant ;
2. produit un dump PostgreSQL au format personnalisé sans propriétaire ;
3. copie les enregistrements déjà chiffrés en lecture seule ;
4. conserve le plan de migrations et la configuration Compose/proxy ;
5. scelle chaque fichier dans `SHA256SUMS`.

Le fichier `.env` est volontairement exclu. Les clés doivent être exportées et conservées
séparément dans un coffre hors ligne avec une procédure de double contrôle. Une sauvegarde
sans les clés est intègre mais indéchiffrable ; une sauvegarde stockée avec les clés ne fournit
plus de séparation de sécurité.

Vérification non destructive :

```sh
sh scripts/verify-backup.sh /chemin/vers/la/sauvegarde
```

Cette commande recalcule les empreintes et demande à `pg_restore --list` de lire la structure
de l'archive. Elle ne se connecte à aucune base de destination et ne restaure rien.

## Restauration

Une restauration doit d'abord être répétée sur une nouvelle stack isolée, avec des volumes
vides créés pour l'exercice. Elle doit démontrer : migrations, connexion, déchiffrement d'un
secret factice, vérification de l'audit et lecture d'un enregistrement factice. Aucun script de
restauration destructive n'est fourni tant que ce scénario n'a pas été validé en CI Docker.
Ce point reste un bloqueur explicite de la candidate V1.

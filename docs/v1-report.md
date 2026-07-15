# Rapport de construction de PAM-olive V1

## Statut

- Version de départ : 0.2.0
- Cible : 1.0.0
- État actuel : architecture V1 en cours, recette Docker active sur le NAS, non publiable en production
- Environnements modifiés : dépôt local et stack isolée `/volume1/docker/pam-olive`
- NAS : modifications limitées au périmètre explicitement autorisé et inventoriées ci-dessous

## Références analysées

Les guides d'administration, d'audit et d'utilisation WALLIX Bastion 12.3.6 ont été utilisés
comme référence fonctionnelle. Les concepts retenus sont la navigation dépendante du profil,
les profils de permissions, les groupes, la séparation cibles/comptes, les autorisations,
les approbations, la surveillance de session et les historiques d'audit. Aucun code ni élément
de marque propriétaire n'est réutilisé.

## État initial constaté

La v0.2 fournit Django, PostgreSQL, Redis, Channels, Celery, un chiffrement applicatif, des
groupes multiples, des politiques, des demandes, un audit chaîné, un coffre personnel, la MFA
locale et une console moderne. Les principaux écarts V1 sont :

- granularité insuffisante des permissions ;
- absence de profils Approbateur et d'identités externes structurées ;
- connecteurs LDAP/OIDC non implémentés ;
- absence de domaines et de typologie complète des cibles et comptes ;
- workflow d'approbation à décision unique ;
- absence de bail de secret et de rotation orchestrée ;
- courtage et enregistrement SSH/RDP non prêts ;
- observabilité, sauvegarde et restauration encore incomplètes.

## Journal des opérations

### 2026-07-13 - Cadrage V1

- Lecture des modèles et paramètres existants.
- Analyse des sommaires et pages structurantes des trois guides fournis.
- Création du périmètre V1 et de la matrice de permissions.
- Formalisation de la règle de non-modification du NAS.
- Données, Docker et utilisateurs du NAS : aucune opération effectuée.

### 2026-07-13 - Lot identités, permissions et domaines

- Extension des capacités en droits de lecture, gestion et actions sensibles.
- Prise en compte des délégations directes avec dates de début et de fin.
- Ajout du profil système Approbateur et de son groupe dédié.
- Ajout des sources LDAP, Active Directory et OIDC avec configuration chiffrée.
- Ajout des identités externes et des correspondances de groupes.
- Ajout des domaines, types de cibles et types de comptes privilégiés.
- Extension de la console produit sans exposition des secrets de connecteur.
- Migrations vérifiées additives : aucune suppression ni renommage destructif.
- Résultat : 40 tests réussis, couverture 93,86 %, contrôle Django valide.
- Données, Docker et utilisateurs du NAS : aucune opération effectuée.

### 2026-07-13 - Lot fédération et approbations

- Adaptateur LDAP/Active Directory avec TLS, pagination et erreurs non sensibles.
- Synchronisation Celery désactivée par défaut et testée par adaptateur simulé.
- Provisionnement OIDC à la première connexion avec contrôle des groupes.
- Traçabilité de l’origine des appartenances externes afin de préserver les ajouts manuels.
- Révocation des appartenances gérées lorsque le groupe externe disparaît.
- Quorum configurable, groupes d’approbateurs et référence de ticket obligatoire par politique.
- Historique immuable de chaque décision et refus des décisions en double.
- Résultat : 51 tests réussis, couverture 92,68 %, contrôle Django valide.
- Données, Docker et utilisateurs du NAS : aucune opération effectuée.

### 2026-07-13 - Lots baux de secrets et autorisations de session

- Ajout de baux de secrets limités à 15–300 secondes et consommables une seule fois.
- Stockage exclusif du hachage des jetons ; aucun jeton brut n’est persisté.
- Contrôle central des politiques, approbations actives et MFA avant toute consultation.
- Ajout de tickets de session limités à 15–120 secondes, liés à l’utilisateur, au compte,
  à la cible, au protocole, à la politique et à l’adresse d’origine.
- Une approbation valide peut autoriser plusieurs sessions dans sa fenêtre, chacune possédant
  son propre ticket et sa propre trace d’audit.
- Le ticket est envoyé dans le premier message WebSocket et jamais dans une URL HTTP ou
  WebSocket susceptible d’être journalisée.
- L’écran Cibles propose une session uniquement si l’action `start_session` est accordée.
- Réponse terminal marquée `private`, `no-store` et `must-revalidate`.
- Tant que le broker isolé n’est pas disponible, le canal valide le ticket puis termine la
  session en échec avec le motif `gateway_not_configured`. Aucun secret n’est consommé et
  aucune connexion distante n’est tentée : comportement fermé par défaut.
- Migration de session vérifiée : champs additifs, nouveau ticket et assouplissement du lien
  demande/session ; aucune table ni colonne supprimée.
- Résultat : 60 tests réussis, couverture 92,99 %, style et contrôle Django valides.
- Données, Docker et utilisateurs du NAS : aucune opération effectuée.

### 2026-07-13 - Lot intégrité et export d’audit

- Version 2 du journal avec séquence stricte, contenu canonique recalculable et signature HMAC.
- État de tête verrouillé en transaction afin de sérialiser les écritures concurrentes.
- Reprise non destructive des événements v1, conservés et identifiés comme historiques.
- Validation de la continuité, des liens, empreintes, signatures et de la tête de chaîne.
- Export CSV ou JSON Lines limité à 10 000 événements, soumis à `audit.export`.
- Export bloqué avec HTTP 409 si une falsification est détectée.
- Expurgation récursive des mots de passe, secrets, clés, cookies, jetons et tickets présents
  dans les métadonnées ; neutralisation des cellules CSV interprétables comme formules.
- Empreinte SHA-256 fournie avec le téléchargement et export lui-même audité.
- Interface d’audit enrichie avec état d’intégrité, filtres et boutons conditionnels.
- Tests adversariaux par altération directe de la base de test : falsification détectée et
  export refusé comme prévu.
- Résultat : 64 tests réussis, couverture 92,86 %, style et contrôle Django valides.
- Données, Docker et utilisateurs du NAS : aucune opération effectuée.

### 2026-07-13 - Lot broker SSH isolé et confiance d’hôte

- Ajout d’un registre de clés d’hôte SSH avec empreinte SHA-256, approbateur, justification,
  historique et révocation auditée.
- Refus d’émettre un ticket SSH en l’absence d’une clé d’hôte active.
- Broker ASGI séparé : aucun accès à PostgreSQL, Redis, la clé du coffre ou la clé d’audit.
- Protocole interne HMAC horodaté et enveloppe de connexion chiffrée à usage court.
- Le secret est échangé et consommé côté broker ; il n’est jamais envoyé au navigateur.
- Connexion AsyncSSH avec `known_hosts` obligatoire, mot de passe ou clé privée en mémoire.
- Relais terminal WebSocket avec entrée, sortie, redimensionnement et contrôle clavier.
- Enregistrement chiffré de chaque flux, permissions `0600`, empreinte SHA-256 et audit de
  scellement ; aucune donnée de session n’est enregistrée en clair.
- Canal interne de terminaison temps réel signé : état `terminating`, arrêt du processus SSH,
  clôture et rapport au web. Un ticket non consommé est révoqué sans ouvrir le broker.
- Correction d’un scénario de déni de service : un ticket invalide ne peut jamais provoquer
  un rapport de clôture sur la session qu’il prétend viser.
- Test SSH réel sur boucle locale : la clé approuvée connecte et une clé différente échoue.
- Architecture Compose à deux réseaux, proxy Caddy 2.11.4 seul exposé, gateway en lecture
  seule, sans capacités Linux et sans secrets applicatifs. Dix assertions locales réussies.
- Docker n’étant pas installé sur le poste, la validation native `docker compose config` et la
  construction des images restent à exécuter dans un environnement isolé autorisé.
- HTMX 2.0.10 auto-hébergé après vérification SHA-384 ; CSP et en-têtes navigateur stricts.
- Résultat : 79 tests réussis, couverture 90,31 %, style et contrôle Django valides.
- Données, Docker et utilisateurs du NAS : aucune opération effectuée.

### 2026-07-13 - Lot contraintes de politique et préparation GitHub

- Restriction facultative des politiques à des identifiants et protocoles déterminés.
- Périodes de validité, jours de semaine, plages horaires incluant le passage de minuit,
  réseaux sources CIDR et limite de sessions simultanées.
- Application du même moteur de politique aux demandes, baux de secrets et tickets de session.
- Refus fermé des réseaux mal configurés et contrôle de la source transmise par le proxy interne.
- Licence AGPL-3.0-or-later complète et licence Zero-Clause BSD conservée avec HTMX.
- README, politique de sécurité, guide de contribution, notice et code de conduite réécrits
  pour refléter le statut pré-V1 sans promesse de production prématurée.
- CI GitHub avec PostgreSQL, migrations, couverture minimale de 90 %, documentation stricte,
  validation et tests des images Docker.
- Analyse CodeQL, mises à jour Dependabot et pipeline de publication GHCR déclenché uniquement
  par un tag correspondant à la version du projet, avec provenance et SBOM des images.
- Modèles d’issues et de pull request interdisant les secrets et données de systèmes réels.
- Vérification locale : YAML valide, documentation stricte construite, dépendances cohérentes,
  style propre, contrôle Django sans erreur et aucune migration manquante.
- Résultat : 89 tests réussis, couverture 91,43 % sur 2 941 instructions mesurées.
- Le dépôt Git local est autonome mais n’a pas encore de commit ni de dépôt distant ; aucun
  contenu n’a été poussé vers GitHub à ce stade.
- Docker reste absent du poste local : le job GitHub préparé devra encore démontrer la
  construction Compose native dans un environnement éphémère.
- Données, Docker et utilisateurs du NAS : aucune opération effectuée.

### 2026-07-13 - Lot exploitation, rotation et trousseau de clés

- Orchestration idempotente des rotations avec fournisseurs configurables, reprise après échec,
  secret candidat chiffré et promotion uniquement après succès du système cible.
- Planification Celery des rotations arrivées à échéance et console d'historique dédiée.
- Endpoints séparés de vivacité, disponibilité, intégrité et métriques agrégées protégées par
  un jeton d'exploitation distinct.
- Sauvegarde non destructive avec `pg_dump`, enregistrements SSH chiffrés, configuration,
  manifeste SHA-256 et vérification indépendante sans restauration implicite.
- Trousseau multi-clés pour tous les champs chiffrés et commande de rotation transactionnelle,
  en simulation par défaut et avec confirmation explicite pour appliquer.
- Point de contrôle : 102 tests réussis, couverture 90,67 %, style, Django, migrations et
  documentation stricte valides.
- La restauration native reste à répéter dans une stack Docker jetable avant la candidate V1.
- Données, Docker et utilisateurs du NAS : aucune opération effectuée.

### 2026-07-13 - Lot courtage RDP et origine dédiée

- Analyse des sources officielles Apache Guacamole 1.6.0 et vérification du stockage navigateur
  `GUAC_AUTH_TOKEN`, du format `ClientIdentifier` et du contrat `guacamole-auth-json`.
- Origine RDP distincte, broker de lancement minimal, POST sans ticket dans l'URL et page de
  transition avec CSP à nonce et cache interdit.
- Authentification JSON HMAC-SHA256/AES-128-CBC compatible avec l'implémentation Apache,
  expiration à 15 secondes, données et connexion à usage unique.
- Paramètres de cible NLA/NLA étendu/TLS, empreintes de certificat, clavier et redimensionnement.
  Aucun mode `ignore-cert`, `any` ou chiffrement RDP hérité n'est proposé.
- Copie et collage séparés par politique, tous deux refusés par défaut ; lecteur, impression et
  microphone désactivés dans l'enveloppe Guacamole.
- Services Compose Guacamole 1.6.0, guacd, broker et proxy RDP isolés sur quatre réseaux internes.
  `guacd` n'expose aucun port hôte et possède seul la sortie vers les cibles.
- Une régression du formulaire de cible SSH, causée par des champs RDP initialement requis,
  a été détectée par la suite complète puis corrigée par des valeurs RDP conditionnelles.
- Résultat final du lot : 113 tests réussis, couverture 90,57 %, style, Django, migrations,
  scripts, YAML et documentation stricte valides.
- Fermeture forcée, état de fin réel, enregistrement RDP chiffré et validation Docker native
  restent des bloqueurs explicites de candidate V1.
- Données, Docker et utilisateurs du NAS : aucune opération effectuée.

### 2026-07-14 - Recette visuelle, restauration et point de contrôle

- Ajout d'une commande de vérification de restauration en lecture seule : migrations à jour,
  utilisateur témoin facultatif, chaîne d'audit valide et déchiffrement de tous les champs
  protégés.
- Ajout d'un scénario de restauration vers une base PostgreSQL distincte et inexistante. Le
  script exige un accusé explicite, impose un nom de base réservé aux répétitions éphémères et
  ne contient aucune suppression de base, de volume ou de conteneur.
- Recette locale sur une nouvelle base SQLite temporaire avec quatre comptes et uniquement des
  données fictives. La base existante du projet n'a pas été ouverte en écriture.
- Parcours utilisateur validé dans un navigateur réel : connexion, accueil simplifié, coffre
  personnel, identifiants de cibles, révélation auditée du mot de passe et du TOTP, groupes de
  cibles, demandes, compte local et entrée MFA.
- Parcours administrateur validé : console moderne, utilisateurs, groupes multiples, cibles,
  politiques, approbations et audit signé. L'administrateur fonctionnel est refusé sur
  `/django-admin/`.
- Parcours auditeur validé en lecture seule : aucun formulaire de création et aucune action de
  décision sur les approbations.
- Parcours super administrateur validé : accès exclusif à l'administration technique Django.
- Aucun avertissement ni erreur JavaScript relevé pendant la recette.
- Résultat global : 115 tests réussis, couverture applicative 90,69 %, style propre, contrôle
  Django et contrôle de déploiement sans erreur, aucune migration manquante et documentation
  stricte construite.
- La publication GitHub est volontairement reportée à une phase ultérieure à la demande du
  propriétaire du projet. Aucun commit, dépôt distant ou envoi n'a été créé pendant cette phase.
- La validation native de la stack Docker complète, la répétition réelle de restauration,
  l'enregistrement RDP chiffré et la fermeture RDP observée côté Guacamole restent nécessaires
  avant de déclarer une candidate V1 de production.
- Données, Docker et utilisateurs du NAS : aucune opération effectuée.

### 2026-07-14 - Déploiement de recette Docker sur le NAS

- Création d'une stack Compose distincte nommée `pam-olive` dans
  `/volume1/docker/pam-olive`, sans écraser ni modifier `/volume1/docker/cbpam`.
- Transfert d'une archive propre de 303 entrées, vérifiée par SHA-256 avant extraction.
- Génération locale au NAS d'un fichier `.env` en mode `0600`, sans afficher les secrets.
- Exposition du portail sur `0.0.0.0:18081` et de l'origine RDP sur `0.0.0.0:18082`.
- Création de volumes et réseaux Docker dédiés au projet `pam-olive` ; aucune réutilisation
  des volumes de l'ancien PAM.
- Ajout explicite de la dépendance directe `requests`, requise par Authlib au démarrage.
- Compatibilité Synology DSM : attribution de la seule capacité Linux
  `NET_BIND_SERVICE` aux proxies Caddy, tout en conservant le système de fichiers en lecture
  seule, la suppression des autres capacités et `no-new-privileges`.
- Ajout d'un réseau public dédié au seul proxy RDP pour permettre la publication du port sur
  Docker DSM. Le broker, Guacamole et guacd restent compartimentés sur leurs réseaux internes.
- Construction des images, migrations et démarrage des onze services. Les services disposant
  d'un contrôle de santé sont tous déclarés `healthy`.
- Contrôles réseau depuis un autre poste : page de connexion HTTP 200, disponibilité HTTP 200
  et origine RDP HTTP 200.
- Création du super administrateur applicatif `cyriel`, puis connexion réelle validée dans un
  navigateur jusqu'au tableau de bord et à la console `/admin/`.
- Après validation du nouveau portail, arrêt propre et suppression des cinq conteneurs de
  l'ancien projet `cbpam` et des quatre images applicatives `cbpam-*`, conformément à
  l'autorisation du propriétaire.
- Préservation vérifiée de `cbpam_postgres_data`, `cbpam_redis_data` et du dossier
  `/volume1/docker/cbpam`. Aucune commande `prune`, `down -v` ou suppression de volume n'a été
  utilisée.
- Vérification finale : Odoo, Psono et BunkerWeb sont restés actifs et n'ont pas été modifiés.
- GitHub reste volontairement hors périmètre de cette opération.

## Vérifications de référence

Avant le démarrage de la V1, la v0.2 a passé 33 tests avec 94,37 % de couverture sur le NAS.
Ces résultats constituent la ligne de base ; chaque lot V1 devra maintenir ou améliorer ce
niveau sans migration destructive.

## Registre des risques

| Risque | Niveau | Mesure prévue |
| --- | --- | --- |
| Exposition d'un secret dans les journaux | critique | filtrage, tests et objets secrets opaques |
| Escalade de privilèges par cumul de groupes | critique | moteur d'autorisation central et tests négatifs |
| Auto-approbation | élevé | contrainte métier et audit immuable |
| Perte de données pendant une migration | critique | migrations additives et test de mise à niveau |
| Compromission du processus web donnant accès SSH | critique | passerelle isolée et jetons éphémères |
| Réutilisation ou fuite d’un ticket de session | critique | ticket haché, court, usage unique, lié au contexte et absent des URL |
| Indisponibilité LDAP/OIDC | moyen | cache limité, comptes de secours et erreurs explicites |

## Décision de publication

La mention « candidate V1 » ne sera ajoutée que lorsque tous les critères de
`docs/v1-scope.md` seront démontrés par tests et consignés dans ce rapport.

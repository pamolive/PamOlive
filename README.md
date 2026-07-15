# PAM-olive

PAM-olive est une plateforme open source de gestion des accès privilégiés (PAM),
construite avec Django, PostgreSQL, Redis, Celery, une passerelle SSH isolée et
Apache Guacamole pour le courtage RDP HTML5.

> **Statut : pré‑V1.** Le socle fonctionnel et de sécurité est activement développé.
> Cette version n'est pas encore déclarée prête pour une production exposée à
> Internet. La décision de sortie V1 sera documentée, testée et annoncée explicitement.

## Capacités actuelles

- rôles système `superadmin`, `administrator`, `auditor` et `user`, complétés par
  des capacités granulaires ;
- appartenance d'un utilisateur à plusieurs groupes et attributions temporaires ;
- annuaires LDAP/Active Directory et fédération OIDC configurables ;
- groupes de cibles, domaines, comptes locaux et clés d'hôte SSH approuvées ;
- politiques par groupe, cible, identifiant, protocole, réseau, horaire et quota ;
- approbations à quorum, séparation demandeur/approbateur et référence de ticket ;
- coffre personnel chiffré et coffre d'identifiants de cibles ;
- MFA TOTP locale, baux de secrets courts et à usage unique ;
- sessions SSH par ticket éphémère, passerelle isolée et enregistrements chiffrés ;
- lancement RDP gouverné par ticket à usage unique, origine dédiée et Apache Guacamole 1.6.0 ;
- journal d'audit signé, chaîné, vérifiable et exportable ;
- consoles distinctes pour l'utilisateur, l'administration produit et le
  super administrateur Django.

## Architecture

```text
Navigateur
    |
    v
Proxy Caddy  ---- /ws/sessions/* ----> Passerelle SSH isolée ----> Cible SSH
    |
    +----------- application Django ----> PostgreSQL
                         |                 Redis
                         +---------------> Celery

Passerelle ---- enregistrements chiffrés ----> volume dédié
Application ---- événements signés ----------> journal d'audit

Navigateur ---- origine RDP dédiée ----> Broker RDP ----> Guacamole ----> guacd ----> Cible RDP
```

La passerelle ne possède ni accès direct à PostgreSQL, ni fichier `.env` applicatif.
Elle obtient une enveloppe chiffrée à durée de vie courte après validation interne
signée. Le navigateur ne reçoit jamais le secret de la cible. Le courtage RDP est
séparé sur une autre origine afin d'isoler le jeton local de l'interface Guacamole.

## Démarrage local avec Docker Compose

Prérequis : Docker avec le module Compose, OpenSSL sous Linux, ou PowerShell sous
Windows.

```sh
sh scripts/bootstrap.sh
```

Sous Windows :

```powershell
powershell -ExecutionPolicy Bypass -File scripts/bootstrap.ps1
```

Les scripts refusent d'écraser un `.env` existant, génèrent des secrets distincts
pour Django, PostgreSQL, le coffre, l'audit, la passerelle, les enregistrements,
les opérations et l'authentification JSON Guacamole,
puis construisent la stack.

Créer ensuite le premier super administrateur :

```sh
docker compose exec web python manage.py createsuperuser
```

Ouvrir <http://localhost:8000>. L'origine RDP locale est
<http://localhost:8081>. Les interfaces sont :

- `/` : espace utilisateur ;
- `/admin/` : administration produit selon les capacités ;
- `/django-admin/` : administration technique réservée aux super administrateurs.

L'écoute par défaut est limitée à `127.0.0.1`. Le mode HTTP local n'est pas un
point d'entrée Internet. Une exposition publique exige TLS, des noms d'hôtes et
origines explicites, une sauvegarde testée et la configuration de production.

## Tests et qualité

```sh
docker compose --profile test run --rm --build test
```

Le test échoue si une vérification échoue ou si la couverture de `cbpam` descend
sous 90 %. La CI GitHub vérifie également le lint, les migrations, PostgreSQL,
les images Docker et l'analyse CodeQL.

Pour un environnement Python local :

```sh
python -m pip install -e ".[dev]"
ruff check .
python manage.py makemigrations --check --dry-run
pytest --cov=cbpam --cov-fail-under=90
```

## Modèle d'autorisation

Un utilisateur peut appartenir à plusieurs groupes. Une politique relie des groupes
d'utilisateurs à des groupes de cibles et limite les actions, identifiants, protocoles,
réseaux sources, horaires et sessions simultanées. Une autorisation n'est accordée
que si toutes les contraintes applicables sont satisfaites. Les auditeurs peuvent
consulter la configuration et les traces sans obtenir les secrets.

Le détail des capacités est dans [docs/permissions.md](docs/permissions.md) et le
périmètre de sortie dans [docs/v1-scope.md](docs/v1-scope.md). L'architecture et
les limites du courtage RDP sont décrites dans [docs/rdp.md](docs/rdp.md).

## Documentation et contribution

```sh
mkdocs serve
```

La documentation se trouve dans [`docs/`](docs/). Avant toute contribution, lire
[CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) et le
[code de conduite](CODE_OF_CONDUCT.md).

## Licence et indépendance

PAM-olive est distribué sous licence
[GNU AGPL version 3 ou ultérieure](LICENSE). C'est un projet indépendant, non affilié,
non soutenu et non certifié par WALLIX. Les noms et marques de tiers appartiennent
à leurs propriétaires respectifs. Le projet s'inspire de pratiques PAM publiques,
sans reprendre de code propriétaire.

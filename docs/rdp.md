# Courtage RDP avec Apache Guacamole

## Statut

Le lancement RDP gouverné est implémenté et testé sans réseau réel. Il reste **pré-V1** :
la construction native des images, la fermeture forcée d'une session Guacamole active et
l'enregistrement RDP chiffré doivent encore être validés dans une stack Docker isolée.

## Flux de lancement

1. PAM-olive vérifie les groupes, la politique, l'approbation, le MFA, l'origine et le quota.
2. Il crée un ticket de session haché, lié à l'utilisateur et consommable une fois.
3. Le navigateur soumet ce ticket par `POST` à l'origine RDP dédiée. Le ticket n'est jamais
   présent dans une URL.
4. Le broker RDP appelle l'API interne PAM-olive avec une signature HMAC horodatée.
5. L'API consomme le ticket puis un bail de secret à usage unique et retourne une enveloppe
   Fernet au broker.
6. Le broker produit le format officiel `guacamole-auth-json` : HMAC-SHA256, AES-128-CBC,
   IV nul, Base64, expiration à 15 secondes et connexion `singleUse`.
7. Le broker échange ce bloc avec Guacamole côté serveur, puis transmet uniquement le jeton
   Guacamole au navigateur avec une page `no-store` et une CSP à nonce.
8. Guacamole ouvre la connexion via `guacd`. Le secret de la cible ne traverse jamais le
   navigateur.

## Isolation Docker

| Réseau | Membres | Rôle |
| --- | --- | --- |
| `rdp_launch` | proxy RDP, broker RDP | réception du formulaire de lancement |
| `rdp_auth` | broker RDP, Guacamole | échange JSON interne |
| `rdp_frontend` | proxy RDP, Guacamole | interface HTML5 et WebSocket |
| `rdp_guacd` | Guacamole, guacd | protocole Guacamole interne |
| `egress` | guacd | connexion sortante vers les cibles RDP |

`guacd` est un démon passif dépourvu d'authentification propre. Il n'a donc aucun port publié
et n'est joignable que par le conteneur Guacamole.

## Configuration

Variables principales :

```dotenv
CBPAM_RDP_ENABLED=true
CBPAM_RDP_PUBLIC_ORIGIN=https://rdp.pam-olive.example
CBPAM_RDP_HTTP_BIND=127.0.0.1
CBPAM_RDP_HTTP_PORT=8081
CBPAM_GUACAMOLE_JSON_KEY=<32 caractères hexadécimaux aléatoires>
```

En production, `CBPAM_RDP_PUBLIC_ORIGIN` doit être une origine HTTPS sans chemin et différente
de l'origine principale. Le script d'amorçage génère une clé JSON de 128 bits distincte.

Pour chaque cible RDP :

- choisir `nla`, `nla-ext` ou `tls` ; le mode hérité `rdp` et la négociation `any` ne sont pas
  proposés par PAM-olive ;
- conserver `fr-be-azerty` ou sélectionner la disposition réelle du serveur ;
- renseigner les empreintes de certificat au format FreeRDP si la chaîne du serveur n'est pas
  reconnue par le conteneur ;
- ne jamais contourner la validation du certificat. PAM-olive ne génère pas `ignore-cert`.

Les politiques interdisent par défaut la copie depuis la session et le collage vers la session.
Ces droits peuvent être activés indépendamment. Lecteur virtuel, impression et microphone
restent désactivés dans cette version.

## Vérification future dans Docker

À exécuter uniquement sur un environnement de test autorisé :

```sh
docker compose config
docker compose build web gateway rdp-broker
docker compose up -d
docker compose ps
docker compose logs --no-log-prefix rdp-broker guacamole guacd rdp-proxy
```

Le test manuel doit utiliser une cible Windows de laboratoire et une empreinte de certificat
connue. Il doit confirmer le refus d'une mauvaise empreinte, l'usage unique du ticket, les
restrictions du presse-papiers, l'expiration et l'absence de secret dans les journaux.

## Limites bloquant la candidate V1

- aucune preuve native de construction/démarrage Docker n'a encore été produite sur ce poste ;
- la demande d'arrêt administrative RDP ne ferme pas encore de manière démontrée le tunnel
  Guacamole actif ;
- l'enregistrement graphique Guacamole est en clair par défaut. PAM-olive ne l'active donc pas
  tant qu'un scellement chiffré et une suppression vérifiable de la trace temporaire ne sont
  pas implémentés ;
- le suivi exact de fin de session doit être rapproché de l'état réel Guacamole, et non seulement
  de l'expiration de l'autorisation PAM.

## Références officielles

- [Authentification JSON Guacamole 1.6.0](https://guacamole.apache.org/doc/gug/json-auth.html)
- [Configuration RDP](https://guacamole.apache.org/doc/gug/configuring-guacamole.html#rdp)
- [Déploiement Docker Guacamole](https://guacamole.apache.org/doc/gug/guacamole-docker.html)
- [Versions Apache Guacamole](https://guacamole.apache.org/releases/)

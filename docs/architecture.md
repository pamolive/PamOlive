# Architecture

Chaque domaine est une application Django indépendante. Les vues orchestrent les entrées, les services portent les règles métier et les modèles garantissent les invariants persistants.

Le navigateur ne reçoit jamais les identifiants d’une cible. Une passerelle de session dédiée récupère le secret au dernier moment, établit la connexion et diffuse uniquement le terminal ou l’affichage distant.

## Flux d’accès

1. L’utilisateur demande un accès selon une politique.
2. Le moteur vérifie RBAC, MFA, durée et fenêtre temporelle.
3. Un approbateur distinct accepte ou refuse.
4. Une session à durée limitée est créée.
5. La passerelle ouvre la connexion sans exposer le secret.
6. Les événements et la référence d’enregistrement sont audités.

## Isolation des protocoles

SSH est relayé par un broker ASGI dédié qui vérifie la clé d'hôte et chiffre la trace
avant écriture. RDP utilise Apache Guacamole sur une origine distincte. Un broker de
lancement consomme le ticket PAM-olive, obtient le secret via l'API interne signée et
génère une authentification JSON Guacamole expirant après 15 secondes. `guacd` n'est
jamais publié sur un port hôte.

Les réseaux Docker `rdp_launch`, `rdp_auth`, `rdp_frontend` et `rdp_guacd` séparent le
formulaire public, l'échange JSON, l'interface HTML5 et le démon RDP passif. Seul `guacd`
possède un accès sortant vers les cibles. Le détail est dans [RDP](rdp.md).

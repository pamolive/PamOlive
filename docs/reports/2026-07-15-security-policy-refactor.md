# Rapport d’évolution — sécurité, politiques et sessions

Date : 15 juillet 2026
Version : 0.3.0

## Objectif

Cette évolution remplace plusieurs comportements de démonstration par des fonctions métier
durables : cycle de vie MFA, TOTP dynamique, calendriers de droits réutilisables, séparation
des sources d’identité, politiques de rotation et diagnostic explicite des refus de session.

## Travaux réalisés

- MFA TOTP avec dix codes de récupération à usage unique. Seuls leurs condensats sont stockés.
- Renouvellement des codes et réinitialisation MFA après contrôle du mot de passe et d’un second
  facteur valide.
- Rafraîchissement automatique des TOTP toutes les trente secondes, barre de temps et réponse
  HTTP non mise en cache.
- Bouton de masquage qui retire immédiatement le secret du document affiché.
- Objet `TimeFrame` indépendant pour les jours, heures et fenêtres de validité ; une politique
  peut cumuler plusieurs plages.
- Objet `SecretRotationPolicy` indépendant pour la fréquence, la méthode, la longueur générée,
  les groupes de cibles et le connecteur d’exécution.
- Formulaires d’administration compacts basés sur des listes multi-sélection.
- Écrans distincts pour LDAP/Active Directory et OpenID Connect.
- Création de cibles limitée aux équipements SSH et RDP dans cette version.
- Ouverture des sessions dans un nouvel onglet.
- Refus de session présenté dans l’interface PAM-olive avec la mesure corrective attendue.

## Diagnostic de la réponse 403

Les journaux du proxy et de Django ont été corrélés sans modifier la configuration du NAS.
La requête atteignait bien l’application. Elle était refusée parce que la cible SSH ne possédait
aucune clé d’hôte approuvée. Ce contrôle est conservé : il protège contre la connexion à un faux
serveur. L’interface explique désormais qu’un administrateur doit vérifier et approuver la clé
d’hôte dans la console.

## Compatibilité et données

Les anciennes colonnes horaires et de rotation sont conservées pour assurer une migration sans
perte. Les nouveaux objets sont ajoutés par migrations Django. Aucun conteneur tiers, utilisateur
NAS ou volume extérieur au projet PAM-olive n’est modifié.

## Vérifications

- 120 tests automatisés réussis, avec une couverture applicative de 90,71 %.
- Analyse Ruff sans erreur.
- Vérification des migrations Django sans changement manquant.
- Recette Docker isolée réussie avant déploiement sur le NAS.

## Suite avant une V1

La version 0.3.0 reste une version alpha. Les prochains jalons prioritaires sont la validation
réelle des connecteurs LDAP/OIDC, les connecteurs de rotation distants, les parcours SSH/RDP
complets sur plusieurs plateformes, le durcissement de l’exposition TLS et les tests de charge.

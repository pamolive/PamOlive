# Politique de sécurité

La sécurité est une fonction du produit, pas une garantie implicite. PAM-olive est
encore en phase pré‑V1 et ne doit pas être considéré comme certifié ou prêt pour un
déploiement critique sans revue indépendante.

## Versions suivies

| Version | Correctifs de sécurité |
| --- | --- |
| Dernière préversion sur la branche principale | Oui, au mieux des capacités du projet |
| Anciennes préversions | Non |
| `1.x` | Pas encore publiée |

## Signaler une vulnérabilité

Ne publiez jamais une vulnérabilité, un secret, un enregistrement de session ou des
données personnelles dans une issue publique.

Utilisez en priorité **Security → Report a vulnerability** dans le dépôt GitHub afin
d'ouvrir un avis de sécurité privé. Si cette fonction n'est pas encore activée,
contactez le propriétaire du dépôt par un canal privé et demandez un canal chiffré
avant de transmettre les détails.

Le signalement devrait contenir :

- la version ou le commit concerné ;
- le composant et les prérequis ;
- des étapes de reproduction minimales avec des données factices ;
- l'impact attendu et, si possible, une piste de correction ;
- aucune clé, adresse interne ou donnée issue d'un système réel.

## Périmètre particulièrement sensible

- contournement RBAC, de politique, d'approbation ou de MFA ;
- accès inter-utilisateurs aux coffres ou divulgation d'un identifiant de cible ;
- réutilisation d'un bail de secret ou d'un ticket de session ;
- contournement de la vérification des clés d'hôte SSH ;
- falsification ou rupture silencieuse de la chaîne d'audit ;
- évasion de la passerelle, injection de commande ou accès à la base depuis celle-ci ;
- exposition de secrets dans une URL, un journal, un export ou un enregistrement.

## Attentes de déploiement

Les opérateurs doivent fournir des clés aléatoires distinctes, TLS, une politique de
sauvegarde/restauration testée, une rotation des clés, des restrictions réseau et une
supervision. Les exemples et valeurs de CI ne sont jamais des secrets de production.
Consultez [docs/security.md](docs/security.md) avant tout déploiement.

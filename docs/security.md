# Sécurité

- Aucun secret ne doit apparaître dans les journaux, URLs, tâches Celery ou messages WebSocket.
- Les secrets sont chiffrés au repos avec une clé fournie hors base de données.
- Les approbations appliquent la séparation des responsabilités.
- Les événements d’audit sont immuables et chaînés par empreinte.
- La production impose HTTPS, cookies sécurisés, HSTS et origines explicites.
- La passerelle SSH/RDP est un composant séparé et à privilèges minimaux.
- L'interface RDP utilise une origine dédiée afin que son jeton `GUAC_AUTH_TOKEN` ne soit
  pas lisible depuis l'origine principale de PAM-olive.
- Le JSON Guacamole est signé HMAC-SHA256, chiffré AES-128-CBC, valable 15 secondes et
  contient une connexion à usage unique. Il n'est jamais placé dans une URL.
- RDP interdit par défaut copie, collage, lecteur virtuel, impression et microphone. La
  copie et le collage s'activent séparément au niveau d'une politique.
- PAM-olive ne propose aucun équivalent à `ignore-cert` : un certificat RDP doit être
  validé par une autorité reconnue ou par des empreintes FreeRDP configurées.

Ce socle ne constitue pas encore une certification de sécurité. Un modèle de menace, une revue externe et des tests d’intrusion sont requis avant production.

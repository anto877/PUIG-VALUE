# PUIG VALUE V2.5 — Multi-utilisateurs

Le compte défini dans Render devient le Super Administrateur.
Depuis le bouton « Utilisateurs », un administrateur peut créer des comptes Administrateur, Expert ou Consultation, les désactiver, changer leur rôle, changer leur mot de passe ou les supprimer.

Les mots de passe ajoutés sont hachés avec PBKDF2-SHA256 (310 000 itérations) et ne sont jamais stockés en clair.

IMPORTANT : les comptes sont stockés dans SQLite. Pour ne pas les perdre lors d'un redéploiement Render, utilisez un Persistent Disk monté sur /var/data avec PUIG_DATA_DIR=/var/data.

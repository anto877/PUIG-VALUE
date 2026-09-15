# PUIG VALUE V2.4 SECURE

## 1. Mettre les fichiers sur GitHub
Remplacer :
- app/main.py
- app/static/index.html

## 2. Render > votre Web Service > Environment
Ajouter trois variables :

PUIG_ADMIN_USER = choisissez votre identifiant
PUIG_ADMIN_PASSWORD = choisissez un mot de passe fort
PUIG_SESSION_SECRET = 2A3StXCucCYRKw6sskk9yAjAX8qonLjO01D20zx0MZarTwDHWxv5R2UB00vSpr_q

Le SESSION_SECRET ci-dessus est généré aléatoirement pour cette livraison.
Vous pouvez aussi en générer un autre.

## 3. Enregistrer les variables
Render doit redéployer/redémarrer le service après leur ajout.

## Protection
- page principale protégée
- estimation protégée
- DVF protégé
- sauvegardes protégées
- rapports protégés
- cookie HttpOnly
- cookie Secure (HTTPS)
- SameSite=Lax
- signature HMAC-SHA256
- session 12 heures
- bouton Déconnexion
- /api/health reste public uniquement pour Render

IMPORTANT :
Ne mettez jamais PUIG_ADMIN_PASSWORD dans GitHub.
Pour changer le mot de passe plus tard, modifiez simplement
PUIG_ADMIN_PASSWORD dans Render > Environment puis redémarrez/redéployez.

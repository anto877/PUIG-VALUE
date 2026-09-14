# PUIG VALUE™ WEB

Version web serveur de PUIG VALUE, conçue pour fonctionner sur Android, iPhone, PC et tablette.

## Ce qui fonctionne
- Géocodage serveur via Géoplateforme IGN.
- Téléchargement serveur des fichiers DVF géolocalisés par commune.
- Cache local des fichiers DVF : un fichier déjà téléchargé n'est pas redemandé.
- Recherche par rayon et tolérance de surface.
- Filtrage des ventes résidentielles simples.
- Score de pertinence des comparables.
- Valeur pondérée, fourchette, prix conseillé, vente rapide, positionnement ambitieux.
- PUIG Confidence™.
- Historique des estimations en SQLite.
- Interface responsive + impression PDF navigateur.

## Lancer sur un PC avec Docker

```bash
docker compose up --build
```

Puis ouvrir :
http://localhost:8000

## Déployer
Le dépôt contient `render.yaml` et un `Dockerfile`. Il peut être déployé sur tout hébergeur Docker.
Pour Render : créer un nouveau Blueprint/Web Service à partir du dépôt Git contenant ces fichiers.

## Limite actuelle volontaire
La V1 WEB interroge les DVF de la commune géocodée. Le rayon peut s'élargir jusqu'à 3 km,
mais il ne traverse pas encore automatiquement les limites de commune.
La prochaine étape est l'agrégation des communes voisines / PostGIS.

## Données
DVF : https://files.data.gouv.fr/geo-dvf/latest/csv/
Géocodage : https://data.geopf.fr/geocodage/search

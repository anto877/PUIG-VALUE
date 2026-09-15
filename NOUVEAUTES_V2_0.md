# PUIG VALUE WEB V2.0

## Synchronisation DVF
- contrôle automatique toutes les 24 h ;
- cache revérifié après 7 jours ;
- bouton de synchronisation manuelle ;
- années proposées dynamiquement.

## Sauvegarde des estimations
- sauvegarde volontaire ;
- nom de dossier + notes ;
- liste des dossiers ;
- rechargement ;
- suppression.

Pour conserver les dossiers lors de tous les redéploiements Render :
1. ajouter un Persistent Disk ;
2. le monter sur `/var/data` ;
3. ajouter `PUIG_DATA_DIR=/var/data`.

## Rapport d'expertise optionnel
Le rapport est généré uniquement sur demande et contient :
- objet de mission ;
- analyse géographique du macro au micro ;
- description du bien ;
- méthodologie ;
- comparables ;
- régressions ;
- DPE / état ;
- conclusion ;
- sources et réserves.

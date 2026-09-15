# PUIG VALUE V2.3

Correctif du HTTP 500 de la V2.2 :
- `target_n` est maintenant défini avant son utilisation.
- Maison : recherche réellement progressive 100, 200, 300, 400, 500 m puis 750 m, 1 km, 1,5 km, 2 km selon le plafond choisi.
- Le sélecteur est explicitement présenté comme un rayon MAXIMAL : 500 m sélectionné ne signifie pas que la recherche commence à 500 m.
- Appartement : priorité exclusive aux ventes de la même adresse exacte lorsqu'elles existent.

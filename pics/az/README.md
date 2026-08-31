Maintenant le Dockerfile et les fichiers associés :Build :
```bash
docker build -t azure-region-status .
```

Run (produits/régions en listes séparées par virgules → tableau matriciel) :
```bash
docker run --rm azure-region-status \
  "Azure API Management,Azure Kubernetes Service (AKS)/Standard" \
  "westeurope,francecentral"
```

Sortie par défaut = markdown avec icônes :

| Product | westeurope | francecentral |
|---|---|---|
| Azure API Management | ✅ Generally Available | 🧪 In Public Preview |

Options : `--format text|json`, `--no-emoji`, `--debug` (dump HTML/capture dans le conteneur si un produit/colonne n'est pas trouvé — ajoutez `-v $(pwd)/debug:/tmp` pour le récupérer).

Je n'ai pas pu builder/tester l'image ici (réseau sandbox sans accès au registre Docker) — même limite que précédemment sur les sélecteurs DOM, donc testez et ajustez avec `--debug` si besoin.

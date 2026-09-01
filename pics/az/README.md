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




Vérification syntaxe + test réel du mécanisme Selenium (contre une page accessible depuis ce sandbox, pour valider que la logique de clic/scan fonctionne) :Mise à jour du wrapper bash local :Remplacé Playwright par **Selenium**, plus classique/accepté en entreprise.

Build :
```bash
docker build -t azure-region-status .
docker run --rm azure-region-status "Azure API Management,AKS/Standard" "westeurope,francecentral"
```

Base **Debian** (pas Ubuntu) volontairement : `chromium`/`chromium-driver` via `apt` sont de vrais binaires sous Debian, alors que sous Ubuntu ce sont des stubs snap qui ne fonctionnent pas en conteneur — je l'ai vérifié en essayant d'installer chromium ici même.

**Limites honnêtes** :
- Aucun navigateur (Chromium/Firefox) n'est réellement lançable dans mon sandbox (snap bloqué), donc je n'ai pas pu exécuter le script contre le site réel — seulement vérifié la syntaxe et l'API Selenium.
- Hors Docker, réglez `CHROME_BIN`/`CHROMEDRIVER_BIN` si votre Chrome d'entreprise n'est pas à `/usr/bin/chromium`.
- Mêmes réserves qu'avant sur les sélecteurs DOM (texte générique, à ajuster via `--debug` si un produit/région n'est pas trouvé).

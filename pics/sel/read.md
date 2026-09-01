Excellent — tous les wheels sont **pure Python** (`py3-none-any`), donc aucun souci de compatibilité d'architecture. Je les empaquette :Maintenant j'adapte le Dockerfile et le wrapper pour installer depuis ce dossier local, sans jamais toucher PyPI :J'ai téléchargé Selenium + ses 14 dépendances moi-même (tout est `py3-none-any` — pur Python, aucun souci d'architecture) et empaqueté dans `selenium-wheels.zip`.

Arborescence à reconstituer :
```
azure-region-status/
├── Dockerfile
├── requirements.txt
├── azure_region_status.py
├── azure-region-status.sh
└── wheels/          ← extraire selenium-wheels.zip ici
```

Le `Dockerfile` installe maintenant via `pip install --no-index --find-links=/wheels` — **aucun appel à PyPI/files.pythonhosted.org au build**. `apt-get install chromium chromium-driver` reste nécessaire (dépôts Debian officiels) ; prévenez-moi si ceux-ci sont aussi bloqués.

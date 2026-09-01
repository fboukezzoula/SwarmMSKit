# Image pour azure_region_status.py : Python + Selenium + Chromium/chromedriver,
# installés via les paquets Debian officiels (image de base Debian, pas Ubuntu :
# le paquet "chromium" d'Ubuntu n'est qu'un stub snap et ne fonctionne pas en
# conteneur). Aucun téléchargement de binaire tiers à l'exécution.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    CHROME_BIN=/usr/bin/chromium \
    CHROMEDRIVER_BIN=/usr/bin/chromedriver

RUN apt-get update \
    && apt-get install -y --no-install-recommends chromium chromium-driver \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY azure_region_status.py .

ENTRYPOINT ["python3", "azure_region_status.py"]
# Pas de CMD : les paramètres (products, regions, options) sont fournis via `docker run`.

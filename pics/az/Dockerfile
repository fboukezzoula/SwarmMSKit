# Image pour azure_region_status.py : Python + Playwright/Chromium préinstallés.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt \
    && playwright install --with-deps chromium

COPY azure_region_status.py .

ENTRYPOINT ["python3", "azure_region_status.py"]
# Pas de CMD : les paramètres (products, regions, options) sont fournis via `docker run`.

#!/usr/bin/env bash
#
# azure-region-status.sh — Statut d'un produit Azure (GA / Public Preview / Retiring)
# pour une région donnée, lu depuis la page "Products by Region" (mise à jour auto,
# rendue en JS côté client, sans API publique connue -> passage par un navigateur headless).
#
# Usage (sans Docker — utile en développement local) :
#   ./azure-region-status.sh "<Product|Product/SKU>[,...]" "<Region>[,...]" [--format markdown|text|json] [--debug]
#
# Exemples :
#   ./azure-region-status.sh "Azure API Management" "westeurope"
#   ./azure-region-status.sh "Azure API Management,AKS/Standard" "westeurope,francecentral"
#
# Pour un usage packagé, voir le Dockerfile fourni à côté de ce script.
#
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
PY_SCRIPT="$SCRIPT_DIR/azure_region_status.py"
VENV_DIR="$SCRIPT_DIR/.venv"

usage() {
    echo "Usage: $0 \"<Product|Product/SKU>\" \"<Region>\" [--debug] [--url URL]" >&2
    exit 2
}

[[ $# -lt 2 ]] && usage

PRODUCT="$1"; shift
REGION="$1"; shift
EXTRA_ARGS=("$@")   # ex: --debug, --url ...

if [[ ! -f "$PY_SCRIPT" ]]; then
    echo "Erreur : $PY_SCRIPT introuvable (doit être à côté de ce script)." >&2
    exit 1
fi

command -v python3 >/dev/null 2>&1 || { echo "python3 requis." >&2; exit 1; }

# Environnement virtuel isolé pour ne pas polluer le système (utile en environnement
# d'entreprise avec contraintes réseau/proxy : respecte http_proxy/https_proxy déjà définis)
if [[ ! -d "$VENV_DIR" ]]; then
    echo "Préparation de l'environnement (première exécution)..." >&2
    python3 -m venv "$VENV_DIR"
fi
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

if ! python3 -c "import playwright" >/dev/null 2>&1; then
    echo "Installation de Playwright..." >&2
    pip install --quiet --upgrade pip
    pip install --quiet playwright
    python3 -m playwright install --with-deps chromium
fi

set +e
python3 "$PY_SCRIPT" "$PRODUCT" "$REGION" "${EXTRA_ARGS[@]}"
STATUS_CODE=$?
set -e

deactivate 2>/dev/null || true
exit $STATUS_CODE

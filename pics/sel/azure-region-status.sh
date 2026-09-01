#!/usr/bin/env bash
#
# azure-region-status.sh — Statut d'un produit Azure (GA / Public Preview / Retiring)
# pour une ou plusieurs régions, lu depuis la page "Products by Region" via Selenium
# + un Chrome/Chromium déjà installé sur la machine (aucun téléchargement de navigateur).
#
# Usage (hors Docker) :
#   ./azure-region-status.sh "<Product|Product/SKU>[,...]" "<Region>[,...]" [options]
#
# Variables d'environnement (si Chrome/chromedriver ne sont pas aux chemins par défaut) :
#   CHROME_BIN=/opt/google/chrome/chrome CHROMEDRIVER_BIN=/usr/local/bin/chromedriver \
#     ./azure-region-status.sh "..." "..."
#
# Pour un usage packagé et reproductible, voir le Dockerfile fourni à côté de ce script.
#
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
PY_SCRIPT="$SCRIPT_DIR/azure_region_status.py"
VENV_DIR="$SCRIPT_DIR/.venv"

usage() {
    echo "Usage: $0 \"<Product|Product/SKU>[,...]\" \"<Region>[,...]\" [--format markdown|text|json] [--debug]" >&2
    exit 2
}

[[ $# -lt 2 ]] && usage

PRODUCTS="$1"; shift
REGIONS="$1"; shift
EXTRA_ARGS=("$@")

[[ -f "$PY_SCRIPT" ]] || { echo "Erreur : $PY_SCRIPT introuvable." >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 requis." >&2; exit 1; }

CHROME_BIN="${CHROME_BIN:-/usr/bin/chromium}"
CHROMEDRIVER_BIN="${CHROMEDRIVER_BIN:-/usr/bin/chromedriver}"

if [[ ! -x "$CHROME_BIN" ]]; then
    echo "Attention : $CHROME_BIN introuvable. Définissez \$CHROME_BIN vers votre binaire Chrome/Chromium." >&2
fi
if [[ ! -x "$CHROMEDRIVER_BIN" ]]; then
    echo "Attention : $CHROMEDRIVER_BIN introuvable. Définissez \$CHROMEDRIVER_BIN vers votre chromedriver." >&2
fi

if [[ ! -d "$VENV_DIR" ]]; then
    echo "Préparation de l'environnement (première exécution)..." >&2
    python3 -m venv "$VENV_DIR"
fi
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

if ! python3 -c "import selenium" >/dev/null 2>&1; then
    echo "Installation de Selenium..." >&2
    pip install --quiet --upgrade pip
    pip install --quiet selenium
fi

set +e
CHROME_BIN="$CHROME_BIN" CHROMEDRIVER_BIN="$CHROMEDRIVER_BIN" \
    python3 "$PY_SCRIPT" "$PRODUCTS" "$REGIONS" "${EXTRA_ARGS[@]}"
STATUS_CODE=$?
set -e

deactivate 2>/dev/null || true
exit $STATUS_CODE

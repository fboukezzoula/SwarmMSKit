#!/usr/bin/env python3
"""
azure_region_status.py — Lit https://azure.microsoft.com/.../products-by-region/table
(page 100% JavaScript, sans API publique connue) via Selenium + Chrome/Chromium
et renvoie le statut de un ou plusieurs Product (ou Product/SKU) pour une ou
plusieurs Region :
  Generally Available | In Public Preview | Retiring | Not available

Sortie par défaut : tableau Markdown (produits en lignes, régions en colonnes).

Nécessite un binaire Chrome/Chromium + chromedriver compatibles, déjà installés
(pas de téléchargement à l'exécution). Chemins surchargeables via :
  --chrome-bin / $CHROME_BIN        (défaut : /usr/bin/chromium)
  --chromedriver-bin / $CHROMEDRIVER_BIN (défaut : /usr/bin/chromedriver)
"""

import argparse
import json
import os
import re
import sys
import time

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException

DEFAULT_URL = "https://azure.microsoft.com/fr-fr/explore/global-infrastructure/products-by-region/table"

STATUS_MAP = {
    "generally available": "Generally Available",
    "disponibilite generale": "Generally Available",
    "ga": "Generally Available",
    "in public preview": "In Public Preview",
    "en preversion publique": "In Public Preview",
    "preview": "In Public Preview",
    "preversion": "In Public Preview",
    "retiring": "Retiring",
    "en cours de retrait": "Retiring",
    "retrait": "Retiring",
    "not available": "Not available",
    "non disponible": "Not available",
}

STATUS_EMOJI = {
    "Generally Available": "✅",
    "In Public Preview": "🧪",
    "Retiring": "⚠️",
    "Not available": "❌",
}


def normalize(s: str) -> str:
    s = s.lower()
    for a, b in (("é", "e"), ("è", "e"), ("ê", "e"), ("à", "a"),
                 ("ù", "u"), ("ç", "c"), ("î", "i"), ("ô", "o")):
        s = s.replace(a, b)
    return re.sub(r"[^a-z0-9]+", "", s)


def map_status(raw: str) -> str:
    n = normalize(raw)
    for key, val in STATUS_MAP.items():
        if normalize(key) in n:
            return val
    return raw.strip() or "Unknown"


def dump_debug(driver, prefix="/tmp/azure-region-status-debug"):
    try:
        driver.save_screenshot(f"{prefix}.png")
        with open(f"{prefix}.html", "w", encoding="utf-8") as f:
            f.write(driver.page_source)
        print(f"[debug] Capture et HTML enregistrés dans {prefix}.png / {prefix}.html", file=sys.stderr)
    except Exception as e:
        print(f"[debug] Échec de la sauvegarde de debug : {e}", file=sys.stderr)


def build_driver(chrome_bin: str, chromedriver_bin: str):
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--window-size=1600,1200")
    options.add_argument("--lang=fr-FR")
    if chrome_bin:
        options.binary_location = chrome_bin

    service = Service(executable_path=chromedriver_bin) if chromedriver_bin else Service()
    try:
        return webdriver.Chrome(service=service, options=options)
    except WebDriverException as e:
        print(f"Erreur : impossible de démarrer Chrome/Chromium ({e}).\n"
              f"Vérifiez --chrome-bin / --chromedriver-bin (ou $CHROME_BIN / $CHROMEDRIVER_BIN).",
              file=sys.stderr)
        sys.exit(1)


def click_matching(driver, patterns, timeout=4.0):
    """Cherche parmi les éléments cliquables usuels un texte matchant un des patterns, puis clique."""
    compiled = [re.compile(p, re.I) for p in patterns]
    end = time.time() + timeout
    while time.time() < end:
        elements = driver.find_elements(
            By.XPATH,
            "//button | //a | //span | //div | //li | //label"
        )
        for el in elements[:3000]:
            try:
                txt = el.text
            except Exception:
                continue
            if not txt or len(txt) > 80:
                continue
            if any(c.search(txt) for c in compiled):
                try:
                    el.click()
                    return True
                except Exception:
                    try:
                        driver.execute_script("arguments[0].click();", el)
                        return True
                    except Exception:
                        continue
        time.sleep(0.3)
    return False


def select_regions(driver, regions, debug: bool):
    click_matching(driver, [
        r"select a geograph", r"sélectionner une géograph", r"select region",
        r"sélectionner.*région", r"select a region",
    ], timeout=5)
    time.sleep(0.5)

    targets = {normalize(r): r for r in regions}
    found = set()

    candidates = driver.find_elements(
        By.XPATH,
        "//label | //li | //span | //div[@role='checkbox'] | //input[@type='checkbox']/following-sibling::label"
    )
    for el in candidates[:6000]:
        if len(found) == len(targets):
            break
        try:
            txt = el.text
        except Exception:
            continue
        if not txt or len(txt) > 80:
            continue
        n = normalize(txt)
        for tn, orig in targets.items():
            if tn and tn not in found and tn in n:
                clicked = False
                try:
                    el.click()
                    clicked = True
                except Exception:
                    try:
                        driver.execute_script("arguments[0].click();", el)
                        clicked = True
                    except Exception:
                        try:
                            cb = el.find_element(By.XPATH, "preceding-sibling::input[@type='checkbox'][1]")
                            cb.click()
                            clicked = True
                        except Exception:
                            pass
                if clicked:
                    found.add(tn)
                break

    if debug:
        missing = [orig for tn, orig in targets.items() if tn not in found]
        if missing:
            print(f"[debug] Régions non trouvées dans le sélecteur : {missing}", file=sys.stderr)

    click_matching(driver, [
        r"^apply$", r"^appliquer$", r"^ok$", r"^voir les produits$",
        r"^view products$", r"^valider$",
    ], timeout=2)
    time.sleep(0.8)


def select_all_products(driver, debug: bool):
    ok = click_matching(driver, [
        r"select all products", r"sélectionner tous les produits",
        r"tout sélectionner", r"select all",
    ], timeout=4)
    if debug and not ok:
        print("[debug] Bouton « select all products » non trouvé.", file=sys.stderr)
    time.sleep(1.0)


def build_matrix(driver, products, regions, timeout: int, debug: bool):
    WebDriverWait(driver, timeout).until(EC.presence_of_element_located((By.TAG_NAME, "table")))

    header_cells = driver.find_elements(By.CSS_SELECTOR, "table th")
    col_map = {}
    for region in regions:
        rn = normalize(region)
        col_index = None
        for i, th in enumerate(header_cells):
            if rn and rn in normalize(th.text):
                col_index = i
                break
        col_map[region] = col_index
        if debug and col_index is None:
            print(f"[debug] Colonne région introuvable pour « {region} »", file=sys.stderr)

    rows = driver.find_elements(By.CSS_SELECTOR, "table tbody tr")
    row_texts = [(row, row.text) for row in rows]

    parsed = []
    for p in products:
        if "/" in p:
            name, sku = p.split("/", 1)
        else:
            name, sku = p, None
        parsed.append((p, name, sku))

    matrix = {}
    for label, name, sku in parsed:
        name_n, sku_n = normalize(name), (normalize(sku) if sku else None)
        target_row = None
        for row, text in row_texts:
            tn = normalize(text)
            if name_n in tn and (sku_n is None or sku_n in tn):
                target_row = row
                break

        matrix[label] = {}
        if target_row is None:
            for region in regions:
                matrix[label][region] = "Not found"
            if debug:
                print(f"[debug] Produit introuvable dans le tableau : « {label} »", file=sys.stderr)
            continue

        cells = target_row.find_elements(By.TAG_NAME, "td")
        for region in regions:
            col_index = col_map.get(region)
            if col_index is None or col_index >= len(cells):
                matrix[label][region] = "N/A"
                continue
            cell = cells[col_index]
            raw = None
            for sel in ("[title]", "[aria-label]"):
                try:
                    status_el = cell.find_element(By.CSS_SELECTOR, sel)
                    raw = status_el.get_attribute("title") or status_el.get_attribute("aria-label")
                    if raw:
                        break
                except Exception:
                    continue
            if not raw:
                raw = cell.text
            matrix[label][region] = map_status(raw or "")

    return matrix


def to_markdown(matrix, regions, emoji=True):
    header = "| Product | " + " | ".join(regions) + " |"
    sep = "|" + "---|" * (len(regions) + 1)
    lines = [header, sep]
    for product, per_region in matrix.items():
        cells = []
        for r in regions:
            status = per_region.get(r, "N/A")
            if emoji:
                icon = STATUS_EMOJI.get(status, "")
                cells.append(f"{icon} {status}".strip())
            else:
                cells.append(status)
        lines.append("| " + product + " | " + " | ".join(cells) + " |")
    return "\n".join(lines)


def to_text(matrix, regions):
    lines = []
    for product, per_region in matrix.items():
        for r in regions:
            lines.append(f"{product} / {r}: {per_region.get(r, 'N/A')}")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(
        description="Statut Azure (GA / Public Preview / Retiring) pour un ou plusieurs "
                    "produits et régions, via la page Products by Region (Selenium)."
    )
    ap.add_argument("products", help="Produit(s), séparés par des virgules. "
                                      "Ex: 'Azure API Management,Azure Kubernetes Service (AKS)/Standard'")
    ap.add_argument("regions", help="Région(s), séparées par des virgules. "
                                     "Ex: 'westeurope,francecentral'")
    ap.add_argument("--url", default=DEFAULT_URL, help="URL de la page (défaut: version fr-fr)")
    ap.add_argument("--timeout", type=int, default=30, help="Timeout en secondes")
    ap.add_argument("--format", choices=["markdown", "text", "json"], default="markdown")
    ap.add_argument("--no-emoji", action="store_true", help="Désactive les icônes dans le tableau Markdown")
    ap.add_argument("--debug", action="store_true", help="Sauvegarde capture d'écran + HTML en cas d'échec")
    ap.add_argument("--chrome-bin", default=os.environ.get("CHROME_BIN", "/usr/bin/chromium"),
                     help="Chemin du binaire Chrome/Chromium")
    ap.add_argument("--chromedriver-bin", default=os.environ.get("CHROMEDRIVER_BIN", "/usr/bin/chromedriver"),
                     help="Chemin du binaire chromedriver")
    args = ap.parse_args()

    products = [p.strip() for p in args.products.split(",") if p.strip()]
    regions = [r.strip() for r in args.regions.split(",") if r.strip()]

    driver = build_driver(args.chrome_bin, args.chromedriver_bin)
    driver.set_page_load_timeout(args.timeout)

    try:
        try:
            driver.get(args.url)
        except TimeoutException:
            pass  # on continue : le DOM peut déjà être exploitable

        WebDriverWait(driver, args.timeout).until(
            lambda d: d.execute_script("return document.readyState") == "complete"
        )

        select_regions(driver, regions, args.debug)
        select_all_products(driver, args.debug)

        try:
            matrix = build_matrix(driver, products, regions, args.timeout, args.debug)
        except TimeoutException:
            print("Erreur : le tableau n'est jamais apparu (sélection région/produit à ajuster ?).",
                  file=sys.stderr)
            if args.debug:
                dump_debug(driver)
            sys.exit(1)

        if args.debug:
            dump_debug(driver)
    finally:
        driver.quit()

    if args.format == "markdown":
        print(to_markdown(matrix, regions, emoji=not args.no_emoji))
    elif args.format == "json":
        print(json.dumps(matrix, ensure_ascii=False, indent=2))
    else:
        print(to_text(matrix, regions))


if __name__ == "__main__":
    main()

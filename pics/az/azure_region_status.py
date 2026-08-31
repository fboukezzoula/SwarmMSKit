#!/usr/bin/env python3
"""
azure_region_status.py — Lit https://azure.microsoft.com/.../products-by-region/table
(page 100% JavaScript, sans API publique connue) via un navigateur headless
et renvoie le statut de un ou plusieurs Product (ou Product/SKU) pour une ou
plusieurs Region :
  Generally Available | In Public Preview | Retiring | Not available

Sortie par défaut : tableau Markdown (produits en lignes, régions en colonnes).
"""

import argparse
import json
import re
import sys

from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

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
    """Minuscule, sans accents/espaces/ponctuation, pour comparaison robuste."""
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


def dump_debug(page, prefix="/tmp/azure-region-status-debug"):
    try:
        page.screenshot(path=f"{prefix}.png", full_page=True)
        with open(f"{prefix}.html", "w", encoding="utf-8") as f:
            f.write(page.content())
        print(f"[debug] Capture et HTML enregistrés dans {prefix}.png / {prefix}.html", file=sys.stderr)
    except Exception as e:
        print(f"[debug] Échec de la sauvegarde de debug : {e}", file=sys.stderr)


def try_click_any(page, patterns, timeout=3000):
    for pat in patterns:
        try:
            loc = page.get_by_text(re.compile(pat, re.I)).first
            loc.click(timeout=timeout)
            return True
        except Exception:
            continue
    return False


def select_regions(page, regions, debug: bool):
    """Ouvre le sélecteur de régions et coche chaque région demandée."""
    try_click_any(page, [
        r"select a geograph", r"sélectionner une géograph", r"select region",
        r"sélectionner.*région", r"select a region",
    ], timeout=5000)
    page.wait_for_timeout(500)

    targets = {normalize(r): r for r in regions}
    found = set()

    candidates = page.locator("label, li, button, span, div[role='checkbox'], input[type='checkbox'] + label")
    count = candidates.count()
    for i in range(min(count, 6000)):
        if len(found) == len(targets):
            break
        try:
            el = candidates.nth(i)
            txt = el.inner_text(timeout=150)
        except Exception:
            continue
        if not txt or len(txt) > 80:
            continue
        n = normalize(txt)
        for tn, orig in targets.items():
            if tn and tn not in found and tn in n:
                try:
                    el.click(timeout=1200)
                    found.add(tn)
                except Exception:
                    try:
                        el.locator("xpath=preceding-sibling::input[@type='checkbox'][1]").click(timeout=1000)
                        found.add(tn)
                    except Exception:
                        pass
                break

    if debug:
        missing = [orig for tn, orig in targets.items() if tn not in found]
        if missing:
            print(f"[debug] Régions non trouvées dans le sélecteur : {missing}", file=sys.stderr)

    try_click_any(page, [
        r"^apply$", r"^appliquer$", r"^ok$", r"^voir les produits$",
        r"^view products$", r"^valider$",
    ], timeout=2000)
    page.wait_for_timeout(800)


def select_all_products(page, debug: bool):
    ok = try_click_any(page, [
        r"select all products", r"sélectionner tous les produits",
        r"tout sélectionner", r"select all",
    ], timeout=4000)
    if debug and not ok:
        print("[debug] Bouton « select all products » non trouvé.", file=sys.stderr)
    page.wait_for_timeout(1000)


def build_matrix(page, products, regions, debug: bool):
    page.wait_for_selector("table", timeout=20000)

    header_cells = page.query_selector_all("table th")
    col_map = {}
    for region in regions:
        rn = normalize(region)
        col_index = None
        for i, th in enumerate(header_cells):
            if rn and rn in normalize(th.inner_text()):
                col_index = i
                break
        col_map[region] = col_index
        if debug and col_index is None:
            print(f"[debug] Colonne région introuvable pour « {region} »", file=sys.stderr)

    rows = page.query_selector_all("table tbody tr")
    row_texts = [(row, row.inner_text()) for row in rows]

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

        cells = target_row.query_selector_all("td")
        for region in regions:
            col_index = col_map.get(region)
            if col_index is None or col_index >= len(cells):
                matrix[label][region] = "N/A"
                continue
            cell = cells[col_index]
            status_el = cell.query_selector("[title], [aria-label]")
            raw = None
            if status_el:
                raw = status_el.get_attribute("title") or status_el.get_attribute("aria-label")
            if not raw:
                raw = cell.inner_text()
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
                    "produits et régions, via la page Products by Region."
    )
    ap.add_argument("products", help="Produit(s), séparés par des virgules. "
                                      "Ex: 'Azure API Management,Azure Kubernetes Service (AKS)/Standard'")
    ap.add_argument("regions", help="Région(s), séparées par des virgules. "
                                     "Ex: 'westeurope,francecentral'")
    ap.add_argument("--url", default=DEFAULT_URL, help="URL de la page (défaut: version fr-fr)")
    ap.add_argument("--timeout", type=int, default=45000, help="Timeout en ms")
    ap.add_argument("--format", choices=["markdown", "text", "json"], default="markdown")
    ap.add_argument("--no-emoji", action="store_true", help="Désactive les icônes dans le tableau Markdown")
    ap.add_argument("--debug", action="store_true", help="Sauvegarde capture d'écran + HTML en cas d'échec")
    args = ap.parse_args()

    products = [p.strip() for p in args.products.split(",") if p.strip()]
    regions = [r.strip() for r in args.regions.split(",") if r.strip()]

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        try:
            page.goto(args.url, wait_until="networkidle", timeout=args.timeout)
        except PWTimeout:
            page.goto(args.url, wait_until="domcontentloaded", timeout=args.timeout)

        select_regions(page, regions, args.debug)
        select_all_products(page, args.debug)

        try:
            matrix = build_matrix(page, products, regions, args.debug)
        except PWTimeout as e:
            print(f"Erreur : tableau introuvable ({e}).", file=sys.stderr)
            if args.debug:
                dump_debug(page)
            browser.close()
            sys.exit(1)

        if args.debug:
            dump_debug(page)

        browser.close()

    if args.format == "markdown":
        print(to_markdown(matrix, regions, emoji=not args.no_emoji))
    elif args.format == "json":
        print(json.dumps(matrix, ensure_ascii=False, indent=2))
    else:
        print(to_text(matrix, regions))


if __name__ == "__main__":
    main()

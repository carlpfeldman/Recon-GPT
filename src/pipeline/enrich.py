# src/pipeline/enrich.py
from __future__ import annotations

import json
import re
import os
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import requests
from datetime import datetime

ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "data"
RUNS_DIR = DATA_DIR / "runs"
KEV_CACHE = DATA_DIR / "kev.json"

# --------------------------
# Component extraction
# --------------------------

def _extract_components_from_httpx_row(row: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Heuristic extraction of product/version from httpx JSONL rows.
    Looks at 'tech' (technology list) and 'title' (sometimes includes versions).
    """
    comps: List[Dict[str, str]] = []
    techs = row.get("tech") or row.get("technology") or []
    title = row.get("title") or ""
    candidates = set()
    for t in techs:
        candidates.add(str(t))
    if title:
        candidates.add(str(title))

    text = " | ".join(candidates)

    patterns: List[Tuple[str, str]] = [
        (r"(Apache(?:\s+httpd)?)\D*(\d+\.\d+(?:\.\d+)?)", "Apache httpd"),
        (r"(nginx)\D*(\d+\.\d+(?:\.\d+)?)", "nginx"),
        (r"(OpenSSL)\D*(\d+\.\d+[a-z]?)", "OpenSSL"),
        (r"(WordPress)\D*(\d+(?:\.\d+)+)", "WordPress"),
        (r"(Apache Tomcat)\D*(\d+(?:\.\d+)+)", "Apache Tomcat"),
        (r"(Spring Framework)\D*(\d+(?:\.\d+)+)", "Spring Framework"),
        (r"(jQuery)\D*(\d+(?:\.\d+)+)", "jQuery"),
    ]

    seen = set()
    for pat, product_name in patterns:
        m = re.search(pat, text, flags=re.IGNORECASE)
        if m:
            version = m.group(2)
            key = (product_name.lower(), version)
            if key not in seen:
                comps.append({"product": product_name, "version": version})
                seen.add(key)
    return comps

def _load_http_jsonl(http_jsonl: Path, max_rows=8000) -> List[Dict[str, Any]]:
    items = []
    if not http_jsonl.exists():
        return items
    with http_jsonl.open("r", encoding="utf-8", errors="ignore") as f:
        for i, line in enumerate(f):
            if i >= max_rows:
                break
            s = line.strip()
            if not s:
                continue
            try:
                items.append(json.loads(s))
            except Exception:
                pass
    return items

# --------------------------
# KEV (CISA Known Exploited Vulns)
# --------------------------

def update_kev_cache(url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json") -> Path:
    KEV_CACHE.parent.mkdir(parents=True, exist_ok=True)
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    KEV_CACHE.write_text(r.text, encoding="utf-8")
    return KEV_CACHE

def _kev_set() -> set:
    if not KEV_CACHE.exists():
        return set()
    try:
        data = json.loads(KEV_CACHE.read_text(encoding="utf-8"))
        cves = {item["cveID"] for item in data.get("vulnerabilities", []) if "cveID" in item}
        return cves
    except Exception:
        return set()

# --------------------------
# NVD basic keyword search
# --------------------------

def nvd_search_product_version(product: str, version: str, api_key: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Simplified NVD query by keyword (product + version). For production fidelity, you can upgrade to CPE-based queries.
    """
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": f"{product} {version}", "resultsPerPage": 200}
    headers = {}
    if api_key:
        headers["apiKey"] = api_key
    r = requests.get(url, params=params, headers=headers, timeout=30)
    r.raise_for_status()
    data = r.json()
    vulns = data.get("vulnerabilities", []) or []
    # Normalize to a compact structure
    out = []
    for v in vulns:
        cve = v.get("cve", {})
        cve_id = cve.get("id")
        desc = ""
        try:
            descs = cve.get("descriptions", [])
            if descs:
                desc = descs[0].get("value", "")
        except Exception:
            pass
        # CVSS attempt
        cvss = None
        metrics = v.get("cve", {}).get("metrics", {})
        for k in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            arr = metrics.get(k)
            if isinstance(arr, list) and arr:
                cvss = arr[0].get("cvssData", {}).get("baseScore")
                break
        out.append({"cve": cve_id, "summary": desc, "cvss": cvss})
    return out

# --------------------------
# OSV hooks (stubbed to extend later)
# --------------------------

def osv_query_examples(component: Dict[str, str]) -> List[Dict[str, Any]]:
    """
    Placeholder for OSV queries. You’d map specific ecosystems (npm, PyPI, Maven)
    once you can identify them from headers/JS manifests. Returning empty for now.
    """
    return []

# --------------------------
# Orchestrator per run
# --------------------------

def enrich_run_with_known_vulns(run_dir: str, nvd_api_key: Optional[str] = None, refresh_kev: bool = False) -> Path:
    """
    For a given run directory:
      - read http.jsonl
      - extract components and versions
      - query NVD for CVEs
      - optionally refresh CISA KEV cache and mark KEV=True on matching CVEs
      - write known_vulns.json
    """
    rd = Path(run_dir)
    http_jsonl = rd / "http.jsonl"
    out_file = rd / "known_vulns.json"

    rows = _load_http_jsonl(http_jsonl)
    comps_seen = set()
    kev = set()
    if refresh_kev:
        try:
            update_kev_cache()
        except Exception:
            pass
    kev = _kev_set()

    results = []
    for row in rows:
        comps = _extract_components_from_httpx_row(row)
        for c in comps:
            key = (c["product"].lower(), c["version"])
            if key in comps_seen:
                continue
            comps_seen.add(key)

            nvd = []
            try:
                nvd = nvd_search_product_version(c["product"], c["version"], api_key=nvd_api_key)
            except Exception:
                nvd = []

            # OSV placeholder (extend when you detect ecosystems)
            osv = []
            try:
                osv = osv_query_examples(c)
            except Exception:
                pass

            # Mark KEV
            for entry in nvd:
                entry["kev"] = bool(entry.get("cve") in kev)

            results.append({
                "component": c,
                "nvd": nvd,
                "osv": osv,
            })

    out_file.write_text(json.dumps({
        "run": rd.name,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "results": results,
    }, indent=2), encoding="utf-8")

    return out_file

# --------------------------
# CLI usage
# --------------------------

def _find_latest_run_dir() -> Optional[Path]:
    if not RUNS_DIR.exists():
        return None
    runs = [p for p in RUNS_DIR.iterdir() if p.is_dir()]
    if not runs:
        return None
    runs.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return runs[0]

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Enrich a run with known vulnerabilities (NVD + CISA KEV).")
    ap.add_argument("--run-dir", help="Path to a specific run directory (data/runs/...). Defaults to latest run if omitted.")
    ap.add_argument("--refresh-kev", action="store_true", help="Download/refresh the CISA KEV cache locally.")
    ap.add_argument("--nvd-api-key", default=os.getenv("NVD_API_KEY"), help="NVD API key for higher rate limits.")
    args = ap.parse_args()

    run_dir = Path(args.run_dir) if args.run_dir else _find_latest_run_dir()
    if not run_dir or not run_dir.exists():
        print("[fatal] No run dir found.")
        raise SystemExit(1)

    if args.refresh_keV:
        try:
            update_kev_cache()
            print("[+] KEV cache refreshed")
        except Exception as e:
            print(f"[warn] KEV refresh failed: {e}")

    out = enrich_run_with_known_vulns(str(run_dir), nvd_api_key=args.nvd_api_key, refresh_kev=args.refresh_kev)
    print(f"[+] Wrote {out}")

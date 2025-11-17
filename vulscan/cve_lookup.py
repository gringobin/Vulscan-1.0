# v u l s c a n / c v e _ l o o k u p . p y
# Multi-source CVE lookup (no external deps!)

import urllib.request
import urllib.parse
import json
import time
import csv
import os

# ---------------- CONFIG -----------------
REQUEST_TIMEOUT = 8
RETRIES = 2
SLEEP_BETWEEN_RETRIES = 1.0
CACHE_TTL_SECONDS = 60 * 60  # 1h
CACHE_DIR = os.path.join(os.path.expanduser("~"), ".vulscan", "cve_cache")
os.makedirs(CACHE_DIR, exist_ok=True)


# ---------------- CACHE SYSTEM -----------------
def _cache_path(key):
    safe = "".join([c if c.isalnum() else "_" for c in key])[:200]
    return os.path.join(CACHE_DIR, safe + ".json")


def _cache_get(key):
    p = _cache_path(key)
    try:
        if not os.path.exists(p):
            return None
        with open(p, "r", encoding="utf-8") as f:
            j = json.load(f)
        if (time.time() - j.get("_ts", 0)) < j.get("_ttl", CACHE_TTL_SECONDS):
            return j.get("data")
    except:
        return None
    return None


def _cache_set(key, data, ttl=CACHE_TTL_SECONDS):
    p = _cache_path(key)
    try:
        with open(p, "w", encoding="utf-8") as f:
            json.dump({"_ts": time.time(), "_ttl": ttl, "data": data}, f)
    except:
        pass


# ---------------- HTTP FETCH -----------------
def _fetch_url(url, headers=None, timeout=REQUEST_TIMEOUT):
    headers = headers or {"User-Agent": "VULSCAN/2.0 (+https://github.com/gringobin/Vulscan-1.0)"}
    for attempt in range(RETRIES + 1):
        try:
            req = urllib.request.Request(url, headers=headers, method="GET")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read(), resp.headers.get("Content-Type", "")
        except:
            if attempt < RETRIES:
                time.sleep(SLEEP_BETWEEN_RETRIES)
                continue
            return None, None
    return None, None


def _safe_json_load(bytestr):
    try:
        return json.loads(bytestr.decode("utf-8", errors="ignore"))
    except:
        return None


# ---------------- PARSERS -----------------
def _parse_circl_search(query):
    key = f"circl:{query}"
    cached = _cache_get(key)
    if cached is not None:
        return cached

    url = f"https://cve.circl.lu/api/search/{urllib.parse.quote(query)}"
    data_bytes, ctype = _fetch_url(url)

    results = []
    if data_bytes and "application/json" in str(ctype):
        j = _safe_json_load(data_bytes)
        if j and isinstance(j.get("results"), list):
            for item in j["results"][:10]:
                results.append({
                    "source": "CIRCL",
                    "id": item.get("id"),
                    "summary": item.get("summary"),
                    "cvss": item.get("cvss"),
                    "refs": item.get("references") or []
                })

    _cache_set(key, results)
    return results


def _parse_nvd_search(query):
    key = f"nvd:{query}"
    cached = _cache_get(key)
    if cached is not None:
        return cached

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={urllib.parse.quote(query)}"
    data_bytes, ctype = _fetch_url(url)

    results = []
    if data_bytes and "json" in str(ctype):
        j = _safe_json_load(data_bytes)
        if j:
            vulns = j.get("vulnerabilities") or []
            for v in vulns[:10]:
                cve = v.get("cve", {})
                cid = cve.get("id")
                summary = None
                for d in cve.get("descriptions", []):
                    if d.get("lang", "").lower() == "en":
                        summary = d.get("value")
                        break
                cvss = None
                metrics = cve.get("metrics") or {}
                try:
                    if "cvssMetricV31" in metrics:
                        cvss = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                    elif "cvssMetricV3" in metrics:
                        cvss = metrics["cvssMetricV3"][0]["cvssData"]["baseScore"]
                    elif "cvssMetricV2" in metrics:
                        cvss = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
                except:
                    pass

                refs = []
                for r in cve.get("references", []):
                    if isinstance(r, dict) and r.get("url"):
                        refs.append(r["url"])

                results.append({
                    "source": "NVD",
                    "id": cid,
                    "summary": summary,
                    "cvss": cvss,
                    "refs": refs
                })

    _cache_set(key, results)
    return results


def _parse_vuldb_search(query):
    key = f"vuldb:{query}"
    cached = _cache_get(key)
    if cached is not None:
        return cached
    _cache_set(key, [])
    return []


def _parse_exploitdb_lookup(query):
    key = f"exploitdb:{query}"
    cached = _cache_get(key)
    if cached is not None:
        return cached
    _cache_set(key, [])
    return []


# ---------------- MERGE & MAIN -----------------
def _merge_results(lists):
    seen = {}
    for lst in lists:
        for item in lst:
            cid = item.get("id") or None
            if not cid:
                continue

            if cid not in seen:
                seen[cid] = {
                    "id": cid,
                    "sources": [],
                    "summary": item.get("summary"),
                    "cvss": item.get("cvss"),
                    "refs": list(item.get("refs") or [])
                }

            seen[cid]["sources"].append(item.get("source"))
            cv = item.get("cvss")
            try:
                if cv is not None and (
                    seen[cid]["cvss"] is None or cv > seen[cid]["cvss"]
                ):
                    seen[cid]["cvss"] = cv
            except:
                pass

            for r in item.get("refs") or []:
                if r not in seen[cid]["refs"]:
                    seen[cid]["refs"].append(r)

    return sorted(seen.values(), key=lambda x: (x.get("cvss") or 0), reverse=True)


def search_cve_multi(service, version=None, detailed=True):
    query = service if not version else f"{service} {version}"
    key = f"multi:{query}"
    cached = _cache_get(key)
    if cached is not None:
        return cached

    merged = _merge_results([
        _parse_circl_search(query),
        _parse_nvd_search(query),
        _parse_vuldb_search(query),
        _parse_exploitdb_lookup(query)
    ])

    _cache_set(key, merged)
    return merged


def get_cves(service, version=None, detailed=True):
    return search_cve_multi(service, version, detailed)


# ---------------- CSV EXPORT -----------------
def export_cves_to_csv(cve_list, outpath):
    fieldnames = ["cve_id", "cvss", "summary", "sources", "refs"]
    try:
        with open(outpath, "w", newline="", encoding="utf-8") as csvf:
            w = csv.DictWriter(csvf, fieldnames=fieldnames)
            w.writeheader()
            for c in cve_list:
                w.writerow({
                    "cve_id": c.get("id"),
                    "cvss": c.get("cvss"),
                    "summary": (c.get("summary") or "").replace("\n", " "),
                    "sources": ";".join(c.get("sources") or []),
                    "refs": ";".join(c.get("refs") or [])
                })
        return True
    except:
        return False

# vulscan/cve_lookup.py
"""
Hybrid CVE lookup backend
MIT License
"""

import requests
import functools
from typing import List, Dict


@functools.lru_cache(maxsize=512)
def hybrid_cve_lookup(product: str, version: str, ttl: int = 72) -> List[Dict]:
    """
    Look up CVEs using OSV → CIRCL → fallback
    """
    results = []

    # 1) OSV.dev
    try:
        r = requests.post(
            "https://api.osv.dev/v1/query",
            json={"query": f"{product} {version}"},
            timeout=10
        )
        if r.status_code == 200:
            data = r.json()
            for item in data.get("vulns", []):
                results.append({
                    "id": item.get("id"),
                    "summary": item.get("summary", "")
                })
            if results:
                return results
    except Exception:
        pass

    # 2) CIRCL
    try:
        r = requests.get(
            f"https://cve.circl.lu/api/search/{product}/{version}",
            timeout=10
        )
        if r.status_code == 200:
            for item in r.json():
                results.append({
                    "id": item.get("id"),
                    "summary": item.get("summary", "")
                })
            if results:
                return results
    except Exception:
        pass

    # 3) sin resultados
    return results


if __name__ == "__main__":
    print(hybrid_cve_lookup("nginx", "1.20"))

# backward compatibility wrapper expected by main
def hybrid_cve_lookup(product, version, ttl=72):
    # ttl ignorado por compatibilidad; simplemente reutiliza get_cves
    return get_cves(product, version, detailed=True)

# v u l s c a n / c v e _ l o o k u p . p y
# Multi-source CVE lookup (no external deps)
import urllib.request
import urllib.parse
import json
import time
import csv
import os

# Config
REQUEST_TIMEOUT = 8
RETRIES = 2
SLEEP_BETWEEN_RETRIES = 1.0
CACHE_TTL_SECONDS = 60 * 60  # 1h
CACHE_DIR = os.path.join(os.path.expanduser("~"), ".vulscan", "cve_cache")
os.makedirs(CACHE_DIR, exist_ok=True)

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

def _fetch_url(url, headers=None, timeout=REQUEST_TIMEOUT):
    # simple fetch with retries, returns tuple (content_bytes, content_type_or_None)
    headers = headers or {"User-Agent": "VULSCAN/1.0 (+https://github.com/gringobin/Vulscan-1.0)"}
    for attempt in range(RETRIES + 1):
        try:
            req = urllib.request.Request(url, headers=headers, method="GET")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                ctype = resp.headers.get("Content-Type", "")
                data = resp.read()
                return data, ctype
        except Exception as e:
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

# --------- Parsers for each source ----------
def _parse_circl_search(query):
    key = f"circl:{query}"
    cached = _cache_get(key)
    if cached is not None:
        return cached
    q = urllib.parse.quote(query, safe="")
    url = f"https://cve.circl.lu/api/search/{q}"
    data_bytes, ctype = _fetch_url(url)
    results = []
    if data_bytes and ctype and "application/json" in ctype:
        j = _safe_json_load(data_bytes)
        if j and isinstance(j.get("results"), list):
            for item in j.get("results", [])[:10]:
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
    # NVD may rate-limit. We try but handle gracefully.
    key = f"nvd:{query}"
    cached = _cache_get(key)
    if cached is not None:
        return cached
    q = urllib.parse.quote(query, safe="")
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={q}"
    data_bytes, ctype = _fetch_url(url)
    results = []
    if data_bytes and ctype and ("application/json" in ctype or "application/vnd.api+json" in ctype):
        j = _safe_json_load(data_bytes)
        if j:
            # new NVD schema: "vulnerabilities" list
            vulns = j.get("vulnerabilities") or j.get("results") or []
            for item in vulns[:10]:
                cve = item.get("cve") or {}
                cid = cve.get("id") or (cve.get("CVE_data_meta") or {}).get("ID")
                # try to extract summary and cvss
                descs = cve.get("descriptions") or []
                summary = None
                if descs and isinstance(descs, list):
                    # pick english
                    for d in descs:
                        if d.get("lang", "").lower() == "en":
                            summary = d.get("value")
                            break
                    if not summary and descs:
                        summary = descs[0].get("value")
                cvss = None
                metrics = cve.get("metrics") or {}
                # try cvss v3.1 then v3.0 then v2
                try:
                    if "cvssMetricV31" in metrics:
                        cvss = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                    elif "cvssMetricV3" in metrics:
                        cvss = metrics["cvssMetricV3"][0]["cvssData"]["baseScore"]
                    elif "cvssMetricV2" in metrics:
                        cvss = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
                except:
                    cvss = None
                refs = []
                for r in cve.get("references", []) if cve.get("references") else []:
                    url_r = r.get("url") if isinstance(r, dict) else None
                    if url_r:
                        refs.append(url_r)
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
    # VulDB has no official free JSON API for anonymous; many times returns HTML.
    key = f"vuldb:{query}"
    cached = _cache_get(key)
    if cached is not None:
        return cached
    q = urllib.parse.quote(query, safe="")
    url = f"https://vuldb.com/?search={q}"
    data_bytes, ctype = _fetch_url(url)
    results = []
    # If HTML is returned, we avoid fragile scraping; return empty and let other sources cover.
    # (If you have an API key for VulDB, we can implement direct API.)
    _cache_set(key, results)
    return results

def _parse_exploitdb_lookup(query):
    # Exploit-DB has downloadable CSV or web UI; for simplicity we try the web query and skip HTML parsing.
    key = f"exploitdb:{query}"
    cached = _cache_get(key)
    if cached is not None:
        return cached
    # No reliable unauthenticated JSON endpoint; return empty
    results = []
    _cache_set(key, results)
    return results

# --------- Coordinator & normalization ----------
def _merge_results(list_of_lists):
    seen = {}
    out = []
    for lst in list_of_lists:
        for item in lst:
            cid = item.get("id") or item.get("CVE") or None
            if not cid:
                # fallback: build synthetic id from summary
                cid = "unknown-" + str(abs(hash(item.get("summary",""))))[:8]
                item["id"] = cid
            key = cid
            if key not in seen:
                seen[key] = {
                    "id": cid,
                    "sources": [],
                    "summary": item.get("summary"),
                    "cvss": item.get("cvss"),
                    "refs": list(item.get("refs") or [])
                }
            # append source
            seen[key]["sources"].append(item.get("source"))
            # prefer higher CVSS if present
            try:
                if item.get("cvss") is not None:
                    if seen[key].get("cvss") is None or (float(item.get("cvss")) > float(seen[key].get("cvss", 0))):
                        seen[key]["cvss"] = item.get("cvss")
            except:
                pass
            # merge refs
            for r in item.get("refs") or []:
                if r not in seen[key]["refs"]:
                    seen[key]["refs"].append(r)
    # build list preserving some order (by cvss desc)
    out = sorted(seen.values(), key=lambda x: (x.get("cvss") or 0), reverse=True)
    return out

def search_cve_multi(service, version=None, detailed=True):
    """
    Main function to call from your scanner.
    Returns list of normalized CVE dicts.
    Each dict: {id, sources, summary, cvss, refs}
    """
    query = service if not version else f"{service} {version}"
    key = f"multi:{query}"
    cached = _cache_get(key)
    if cached is not None:
        return cached

    # Query priority: CIRCL -> NVD -> VulDB -> ExploitDB
    circl = _parse_circl_search(query)
    nvd = _parse_nvd_search(query)
    vuldb = _parse_vuldb_search(query)
    exploitdb = _parse_exploitdb_lookup(query)

    merged = _merge_results([circl, nvd, vuldb, exploitdb])
    _cache_set(key, merged)
    return merged

# Compatibility wrapper for older name
def get_cves(service, version=None, detailed=True):
    return search_cve_multi(service, version, detailed)

# -------------- CSV export helper ----------------
def export_cves_to_csv(cve_list, outpath):
    """
    cve_list: list of dicts returned by search_cve_multi
    outpath: path to CSV file to write
    """
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
    except Exception as e:
        return False

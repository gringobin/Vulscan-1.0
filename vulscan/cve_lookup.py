import urllib.request
import json

def fetch_json(url):
    try:
        with urllib.request.urlopen(url, timeout=8) as response:
            return json.loads(response.read().decode())
    except:
        return None


def search_cve(service, version=None, detailed=True):
    query = service if not version else f"{service} {version}"
    print(f"\n  [+] {query}\n")

    results = []
    keywords = urllib.request.quote(query)

    # 1) CIRCL CVE API
    url1 = f"https://cve.circl.lu/api/search/{keywords}"
    data = fetch_json(url1)
    if data and "results" in data:
        for item in data["results"][:5]:
            results.append({
                "source": "CIRCL",
                "id": item.get("id"),
                "summary": item.get("summary"),
                "cvss": item.get("cvss")
            })

    # 2) NIST NVD API
    url2 = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keywords}"
    data = fetch_json(url2)
    if data and "vulnerabilities" in data:
        for item in data["vulnerabilities"][:5]:
            cve = item.get("cve", {})
            metrics = cve.get("metrics", {})
            cvss = None
            if "cvssMetricV31" in metrics:
                cvss = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
            results.append({
                "source": "NVD",
                "id": cve.get("id"),
                "summary": cve.get("descriptions", [{}])[0].get("value"),
                "cvss": cvss
            })

    # 3) VulDB
    url3 = f"https://vuldb.com/?api&search={keywords}"
    data = fetch_json(url3)
    if data and "result" in data:
        for item in data["result"][:5]:
            results.append({
                "source": "VulDB",
                "id": item.get("entry"),
                "summary": item.get("title"),
                "cvss": item.get("cvss")
            })

    # ==== Output visual ====
    if not results:
        print("   └─ No se encontraron CVE.\n")
        return results

    for i, r in enumerate(results):
        prefix = "└─" if i == len(results)-1 else "├─"
        cvss = f"(CVSS {r['cvss']})" if r['cvss'] else ""
        print(f"   {prefix} [{r['source']}] {r['id']} {cvss}")

        if detailed and r['summary']:
            print(f"       {r['summary']}\n")

    return results

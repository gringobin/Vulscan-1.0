import requests

class CVEAggregator:

    def fetch_cve_by_cpe(self, cpe):
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {"cpeName": cpe}
        r = requests.get(url, params=params, timeout=8)

        if r.status_code != 200:
            return []

        data = r.json()
        vulns = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            vulns.append({
                "id": cve.get("id"),
                "description": cve.get("descriptions", [{}])[0].get("value", "")
            })
        return vulns

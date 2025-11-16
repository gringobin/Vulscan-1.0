import requests

def get_cves(service, version):
    try:
        query = f"{service} {version}".replace(" ", "%20")
        url = f"https://cve.circl.lu/api/search/{query}"
        res = requests.get(url, timeout=4)

        if res.status_code != 200:
            return []

        data = res.json()

        cves = []
        for item in data[:5]:
            cves.append({
                "id": item.get("id"),
                "summary": item.get("summary"),
                "cvss": item.get("cvss")
            })

        return cves

    except:
        return []
def print_report(results):
    for r in results:
        print(f"\n[+] Puerto {r['port']} abierto ({r['service']})")
        print(f"    Versión detectada: {r['version']}")

        if r["cves"]:
            print("    Vulnerabilidades encontradas:")
            for c in r["cves"]:
                print(f"     - {c['id']} (CVSS: {c['cvss']})")
                print(f"       {c['summary'][:80]}...")
        else:
            print("    Sin CVEs conocidas.")
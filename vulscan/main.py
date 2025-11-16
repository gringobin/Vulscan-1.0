from .banner import banner
from .scanner import scan_ports_and_services
from .cve_lookup import get_cves
from .report import print_report
import argparse

def main():
    banner()

    parser = argparse.ArgumentParser(description="VULSCAN - Port, Service & Vulnerability Scanner")
    parser.add_argument("target", help="IP o dominio objetivo")
    parser.add_argument("-q", "--quick", action="store_true", help="Escaneo rápido")
    args = parser.parse_args()

    print(f"[+] Escaneando objetivo: {args.target}\n")

    results = scan_ports_and_services(args.target, quick=args.quick)

    print("\n[+] Buscando vulnerabilidades en CVE...\n")
    for r in results:
        service = r.get("service")
        version = r.get("version")

        if service and version:
            r["cves"] = get_cves(service, version)
        else:
            r["cves"] = []

    print_report(results)
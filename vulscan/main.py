import argparse
import sys
import os
from .scanner import scan_ports_and_services
from .cve_lookup import get_cves, export_cves_to_csv
from .reporting.json_report import export_json
from .reporting.html_report import export_html
from .reporting.pdf_report import export_pdf


def print_banner():
    print(r"""
██╗   ██╗██╗   ██╗██╗     ███████╗ ██████╗ █████╗ ███╗   ██╗
██║   ██║██║   ██║██║     ██╔════╝██╔════╝██╔══██╗████╗  ██║
██║   ██║██║   ██║██║     ███████╗██║     ███████║██╔██╗ ██║
╚██╗ ██╔╝██║   ██║██║     ╚════██║██║     ██╔══██║██║╚██╗██║
 ╚████╔╝ ╚██████╔╝███████╗███████║╚██████╗██║  ██║██║ ╚████║
  ╚═══╝   ╚═════╝ ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝

        V U L S C A N   v2.0  -  Enhanced Reporting Edition
    """)


def print_cve_compact(cve):
    cid = cve.get("id")
    cvss = cve.get("cvss")
    summary = cve.get("summary") or ""
    print(f"   → {cid} | CVSS: {cvss} | {summary[:120]}")


def print_cve_details(cve):
    print("=" * 70)
    print(f"📌 CVE:   {cve.get('id')}")
    print(f"🌡 CVSS:  {cve.get('cvss')}")
    print(f"📚 Fuentes: {', '.join(cve.get('sources') or [])}")
    print(f"📝 Descripción:\n{cve.get('summary')}\n")
    if cve.get("refs"):
        print("🔗 Referencias:")
        for r in cve["refs"][:10]:
            print("   -", r)
    print()


def scan_cves_for_target(results, full=False):
    cve_results = []

    print("\n[+] Buscando vulnerabilidades en CVE...\n")

    for entry in results:
        port = entry["port"]
        service = entry["service"]
        version = entry.get("version")

        print(f"[+] {service} ({port}) - buscando CVEs...")

        cves = get_cves(service, version, detailed=full)

        if not cves:
            print("   → No se encontraron resultados\n")
            continue

        print(f"   → {len(cves)} vulnerabilidades encontradas")

        for c in cves[:10]:
            if full:
                print_cve_details(c)
            else:
                print_cve_compact(c)

        cve_results.extend(cves)

    return cve_results


def main():
    parser = argparse.ArgumentParser(description="Vulscan - Port & CVE Scanner")
    parser.add_argument("target", help="IP o dominio a escanear")
    parser.add_argument("-q", "--quick", action="store_true",
                        help="Escaneo rápido (solo puertos comunes)")
    parser.add_argument("--full", action="store_true",
                        help="Mostrar detalles completos de vulnerabilidades")
    parser.add_argument("--export", metavar="FILE",
                        help="Exportar resultados CVE a CSV")
    parser.add_argument("--report", metavar="FILE",
                        help="Generar reporte JSON / HTML / PDF")

    args = parser.parse_args()

    print_banner()
    print(f"[+] Escaneando objetivo: {args.target}\n")

    results = scan_ports_and_services(args.target, quick=args.quick)

    print("\n\n[+] Puertos abiertos encontrados:\n")
    for r in results:
        print(f"   → {r['port']}/tcp  {r['service']}  {r.get('version') or ''}")
    print()

    cve_results = scan_cves_for_target(results, full=args.full)

    # CSV Export (original)
    if args.export and cve_results:
        print(f"\n[+] Exportando CVEs a CSV: {args.export}")
        if export_cves_to_csv(cve_results, args.export):
            print("[✓] Exportación CSV completada")
        else:
            print("[!] Error al escribir archivo CSV")

    # New: JSON / HTML / PDF Export
    if args.report:
        out = args.report
        ext = os.path.splitext(out)[1].lower()

        print(f"\n[+] Generando reporte: {out}")

        if ext == ".json":
            if export_json(args.target, results, cve_results, out):
                print("[✓] Reporte JSON guardado")
            else:
                print("[!] Error generando JSON")

        elif ext == ".html":
            if export_html(args.target, results, cve_results, out):
                print("[✓] Reporte HTML guardado")
            else:
                print("[!] Error generando HTML")

        elif ext == ".pdf":
            ok, msg = export_pdf(args.target, results, cve_results, out)
            if ok:
                print("[✓] Reporte PDF guardado")
            else:
                print(f"[!] No se generó PDF: {msg}")

        else:
            print("[!] Formato inválido. Usa .json .html o .pdf")

    print("\n[✔] Finalizado.\n")


if __name__ == "__main__":
    main()

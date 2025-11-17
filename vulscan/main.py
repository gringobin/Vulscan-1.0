#!/usr/bin/env python3
"""
Vulscan Professional CLI
MIT License
"""
# Scanner selection: improved → legacy fallback
try:
    # si hay un módulo mejorado disponible, úsalo y alinéalo a scan_target
    from .improved_scanner import improved_sync_scan as scan_target
except Exception:
    # fallback: el scanner actual define scan_ports_and_services
    from .scanner import scan_ports_and_services as scan_target
import json
import argparse
import logging
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

# Scanner selection: improved → legacy fallback
try:
    from .improved_scanner import improved_sync_scan as scan_target
except ImportError:
    from .scanner import scan_ports_and_services as scan_target

from .cve_lookup import hybrid_cve_lookup


console = Console()
log = logging.getLogger("vulscan")

# ---------------------------------------------------------------------------
# Export Helpers
# ---------------------------------------------------------------------------
def export_json(results, filename: str):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    console.print(f"[green]✓ Exported JSON to:[/green] {filename}")


def export_html(results, filename: str):
    from .reporting.html_export import generate_html_report
    generate_html_report(results, filename)
    console.print(f"[green]✓ Exported HTML report to:[/green] {filename}")


def export_pdf(results, filename: str):
    from .reporting.pdf_export import generate_pdf_report
    generate_pdf_report(results, filename)
    console.print(f"[green]✓ Exported PDF report to:[/green] {filename}")


# ---------------------------------------------------------------------------
# Rendering results in console
# ---------------------------------------------------------------------------
def render_table(results):
    table = Table(title="Vulscan Results", show_lines=True)

    table.add_column("Port", justify="center")
    table.add_column("Service", justify="left")
    table.add_column("Version", justify="left")
    table.add_column("CVEs", justify="left")

    for service in results.get("services", []):
        cves = service.get("cves", [])
        cve_str = "\n".join([f"[red]{c['id']}[/red]" for c in cves]) if cves else "-"
        table.add_row(
            str(service.get("port")),
            service.get("service", "-"),
            service.get("version", "-"),
            cve_str,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# Main Vulscan Execution
# ---------------------------------------------------------------------------
def run_vulscan(target: str, export: str = None, ttl: int = 72):
    """
    Runs improved sync scan if available, otherwise fallback.
    Then performs hybrid CVE lookup.
    """

    console.print(f"[bold cyan]🚀 Starting Vulscan on:[/bold cyan] {target}\n")

    # Detect improved scanner
    try:
        from .improved_scanner import improved_sync_scan
        scanner = improved_sync_scan
        log.info("Using improved sync scanner.")
    except ImportError:
        scanner = scan_target
        log.info("Using legacy scanner.")

    scan_data = scanner(target)

    # Perform CVE lookup with OSV → CIRCL → NVD fallback and cache
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        task = progress.add_task("Checking CVEs...", total=None)
        for service in scan_data.get("services", []):
            version = service.get("version")
            product = service.get("service")

            if version:
                service["cves"] = hybrid_cve_lookup(product, version, ttl=ttl)
        progress.update(task, description="CVE analysis complete!")

    # Render table results
    render_table(scan_data)

    # Export options
    if export:
        output = Path(export)
        if output.suffix == ".json":
            export_json(scan_data, export)
        elif output.suffix == ".html":
            export_html(scan_data, export)
        elif output.suffix == ".pdf":
            export_pdf(scan_data, export)
        else:
            console.print("[yellow]⚠ Unsupported export format[/yellow]")

    return scan_data

# ---------------------------------------------------------------------------
# Entry point CLI
# ---------------------------------------------------------------------------
def main():
    parser = build_cli()
    args = parser.parse_args()

    if args.target is None:
        console.print("[red]No target specified.[/red]")
        parser.print_help()
        return

    run_vulscan(
        target=args.target,
        export=args.export,
        ttl=args.ttl
    )


if __name__ == "__main__":
    main()

def build_cli():
    import argparse
    p = argparse.ArgumentParser(prog="vulscan")
    p.add_argument("target", nargs="?", help="Target IP or domain")
    p.add_argument("-q","--quick", action="store_true", help="Quick scan")
    p.add_argument("-e","--export", help="Export file (.json/.html/.pdf)")
    p.add_argument("--ttl", type=int, default=72, help="CVE cache TTL hours")
    return p

def main():
    parser = build_cli()
    args = parser.parse_args()
    if not args.target:
        parser.print_help()
        return 1
    # call existing run function (name in your code might be run_vulscan or similar)
    run_vulscan(args.target, export=args.export, ttl=args.ttl)
    return 0

if __name__ == "__main__":
    exit(main())

# -

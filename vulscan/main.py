#!/usr/bin/env python3
"""
Vulscan Professional CLI
MIT License
"""

import json
import argparse
import logging
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from .scanner import scan_target
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


# -

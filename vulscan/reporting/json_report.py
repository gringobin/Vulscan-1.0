# json_report.py
import json
from datetime import datetime

def build_report_obj(target, scan_info, cve_list):
    """
    scan_info: list of dicts from scanner (port, service, version)
    cve_list: list of dicts returned by get_cves (normalized)
    """
    report = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "tool": "Vulscan",
        "version": "v2.0",
        "target": target,
        "summary": {
            "open_ports": len(scan_info),
            "cves_found": len(cve_list)
        },
        "ports": scan_info,
        "cves": cve_list
    }
    return report

def export_json(target, scan_info, cve_list, outpath):
    report = build_report_obj(target, scan_info, cve_list)
    try:
        with open(outpath, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        return False

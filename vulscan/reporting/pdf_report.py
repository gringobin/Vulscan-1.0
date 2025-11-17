# pdf_report.py
import shutil
import subprocess
import os
from .html_report import export_html, ASCII_LOGO
from datetime import datetime

def export_pdf(target, scan_info, cve_list, outpath):
    # create temporary html file
    tmp_html = outpath + ".tmp.html"
    ok = export_html(target, scan_info, cve_list, tmp_html)
    if not ok:
        return False, "Failed to create intermediate HTML"

    # check wkhtmltopdf
    wk = shutil.which("wkhtmltopdf")
    if wk is None:
        # cleanup temp and return path to HTML instead
        os.replace(tmp_html, outpath + ".html")
        return False, "wkhtmltopdf not installed. HTML saved as " + (outpath + ".html")

    # generate pdf
    try:
        # basic flags: disable smart-shrinking for better layout
        subprocess.run([wk, "--enable-local-file-access", tmp_html, outpath], check=True, timeout=60)
        os.remove(tmp_html)
        return True, "PDF generated"
    except subprocess.CalledProcessError as e:
        return False, f"wkhtmltopdf failed: {e}"
    except Exception as e:
        return False, str(e)

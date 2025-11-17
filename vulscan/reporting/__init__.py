# Permite importar los módulos de reportes
from .json_report import export_json
from .html_report import export_html

__all__ = [
    "export_json",
    "export_html",
]

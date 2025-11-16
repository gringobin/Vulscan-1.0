import re

def extract_version(banner: str) -> str:
    """
    Extrae versión probable de un banner usando regex.
    """
    match = re.search(r"([A-Za-z0-9\./_-]+)\s*\(?(version )?([\d\.]+)", banner, re.IGNORECASE)
    if match:
        return match.group(0)
    return "unknown"

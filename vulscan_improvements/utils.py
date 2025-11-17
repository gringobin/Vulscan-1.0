import re

def normalize_banner(banner: str) -> str:
    return banner.lower().strip()

def extract_version(banner: str):
    match = re.search(r"([\d]+\.[\d]+\.[\d]+)", banner)
    if match:
        return banner.split("/")[0], match.group(1)
    return banner.split("/")[0], None

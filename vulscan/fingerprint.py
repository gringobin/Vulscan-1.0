import re

def extract_version_from_banner(banner, service):
    if not banner:
        return None
    
    banner = banner.lower()
    service = service.lower()

    patterns = [
        rf"{service}[/\s]?([0-9]+(?:\.[0-9]+)+)",
        r"version[/\s]?([0-9]+(?:\.[0-9]+)+)",
        r"([0-9]+(?:\.[0-9]+)+)"
    ]

    for pattern in patterns:
        match = re.search(pattern, banner)
        if match:
            return match.group(1)
    
    return None

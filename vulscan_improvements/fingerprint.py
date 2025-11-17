import re
from utils import normalize_banner

def fingerprint_service(banner):
    banner = normalize_banner(banner)

    fingerprints = {
        r"apache/?([\d\.]+)?": ("httpd", "apache"),
        r"nginx/?([\d\.]+)?": ("httpd", "nginx"),
        r"openssh_([\d\.]+)": ("ssh", "openssh"),
        r"proftpd/?([\d\.]+)?": ("ftp", "proftpd"),
    }

    for pattern, (service, product) in fingerprints.items():
        match = re.search(pattern, banner)
        if match:
            version = match.group(1) if match.group(1) else None
            return service, product, version

    return "unknown", "unknown", None


def to_cpe(service, product, version):
    if service == "unknown":
        return None
    if version:
        return f"cpe:2.3:a:{product}:{product}:{version}:*:*:*:*:*:*:*"
    return f"cpe:2.3:a:{product}:{product}:*:*:*:*:*:*:*:*"

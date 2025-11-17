import ssl, socket
from datetime import datetime

def get_tls_info(target, port=443):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((target, port), timeout=2) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                return {
                    "issuer": dict(cert["issuer"][0]).get("organizationName"),
                    "cn": dict(cert["subject"][0]).get("commonName"),
                    "expires": cert["notAfter"],
                    "valid_until": datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                }
    except:
        return None

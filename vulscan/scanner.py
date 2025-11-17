import ssl
from datetime import datetime
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from .ports import COMMON_PORTS
from .utils import extract_version

FINGERPRINT_PAYLOADS = {
    21: b"QUIT\r\n",
    22: b"",
    25: b"EHLO example.com\r\n",
    53: b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01",
    80: b"HEAD / HTTP/1.0\r\n\r\n",
    110: b"QUIT\r\n",
    143: b"a1 CAPABILITY\r\n",
    443: b"HEAD / HTTP/1.0\r\n\r\n",
    3306: b"",
    6379: b"PING\r\n",
}

def fingerprint_banner(sock, port):
    payload = FINGERPRINT_PAYLOADS.get(port, b"")
    try:
        if payload:
            sock.send(payload)
        return sock.recv(2048).decode(errors="ignore")
    except:
        return ""

SSL_PORTS = {443, 465, 993, 995, 587, 8443, 9443}

def scan_single_port(target, port):
    s = socket.socket()
    s.settimeout(0.4)
    
    try:
        s.connect((target, port))
        service = COMMON_PORTS.get(port, "unknown")
        banner = fingerprint_banner(s, port)
        version = extract_version(banner)

        ssl_info = fingerprint_ssl(target, port) if port in SSL_PORTS else None

        return {
            "port": port,
            "service": service,
            "version": version,
            "banner": banner.strip(),
            "ssl": ssl_info
        }

    except:
        return None
    finally:
        s.close()


def scan_ports_and_services(target, quick=False, threads=100):
    ports = list(COMMON_PORTS.keys()) if quick else list(range(1, 1025))
    results = []
    total = len(ports)

    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_port = {executor.submit(scan_single_port, target, port): port for port in ports}

        for i, future in enumerate(as_completed(future_to_port), start=1):
            percent = (i / total) * 100
            sys.stdout.write(f"\rProgreso: {percent:.1f}% ({i}/{total} puertos)")
            sys.stdout.flush()

            result = future.result()
            if result:
                results.append(result)

    print()
    return sorted(results, key=lambda x: x["port"])


def fingerprint_ssl(target, port):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((target, port), timeout=1) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()

                return {
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "notBefore": cert.get("notBefore"),
                    "notAfter": cert.get("notAfter"),
                    "serialNumber": cert.get("serialNumber"),
                }
    except:
        return None


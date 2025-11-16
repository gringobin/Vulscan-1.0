import socket
import sys
from .ports import COMMON_PORTS
from .utils import extract_version

def scan_ports_and_services(target, quick=False):
    open_ports = []

    ports = list(COMMON_PORTS.keys()) if quick else list(range(1, 1025))
    total = len(ports)

    for i, port in enumerate(ports, start=1):
        s = socket.socket()
        s.settimeout(0.3)
        try:
            s.connect((target, port))
            service = COMMON_PORTS.get(port, "unknown")

            try:
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = s.recv(1024).decode(errors="ignore")
            except:
                banner = ""

            version = extract_version(banner)

            open_ports.append({
                "port": port,
                "service": service,
                "version": version
            })

        except:
            pass
        finally:
            s.close()

        percent = (i / total) * 100
        sys.stdout.write(f"\rProgreso: {percent:.1f}% ({i}/{total} puertos)")
        sys.stdout.flush()

    print()  # salto de línea al terminar
    return open_ports

import socket

COMMON_PORTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    3306: "mysql",
    3389: "rdp"
}

def scan_ports_and_services(target, quick=False):
    open_ports = []

    ports = COMMON_PORTS.keys() if quick else range(1, 1025)

    for port in ports:
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

    return open_ports

def extract_version(banner):
    if "Server:" in banner:
        try:
            return banner.split("Server:")[1].split("\n")[0].strip()
        except:
            return None
    return None
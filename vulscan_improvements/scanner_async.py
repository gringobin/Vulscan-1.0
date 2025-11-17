import asyncio
import socket
import ssl
from utils import normalize_banner, extract_version


class AsyncPortScanner:
    def __init__(self, concurrency=200, timeout=3):
        self.semaphore = asyncio.Semaphore(concurrency)
        self.timeout = timeout

    async def scan_port(self, host, port):
        async with self.semaphore:
            try:
                conn = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)

                # Enviar payload mínimo para banner grabbing
                try:
                    writer.write(b"\r\n\r\n")
                    await writer.drain()
                    banner = await asyncio.wait_for(reader.read(1024), timeout=1.5)
                except:
                    banner = b""

                writer.close()
                await writer.wait_closed()

                banner_text = banner.decode(errors="ignore")
                service, version = extract_version(normalize_banner(banner_text))

                return {
                    "port": port,
                    "state": "open",
                    "banner": banner_text.strip(),
                    "service": service,
                    "version": version,
                }

            except Exception:
                return {"port": port, "state": "closed"}

    async def run(self, host, ports):
        tasks = [self.scan_port(host, port) for port in ports]
        return await asyncio.gather(*tasks)


async def scan_target(host, ports):
    scanner = AsyncPortScanner()
    return await scanner.run(host, ports)

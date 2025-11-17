# Vulscan Improvements (async engine)

Este módulo mejora el motor actual sin depender de Nmap.

## Capacidades nuevas
✔ Escaneo asíncrono de puertos (muy rápido).  
✔ Banner grabbing automático.  
✔ Identificación preliminar de servicio + versión.  
✔ Generación de CPE para correlación CVE.  
✔ Consultas a NVD sin API key.

## Uso sugerido
```python
import asyncio
from scanner_async import scan_target
from cve_aggregator import CVEAggregator
from fingerprint import to_cpe

result = asyncio.run(scan_target("192.168.0.10", [22,80,443]))

for r in result:
    if r["state"] == "open" and r.get("version"):
        cpe = to_cpe(r["service"], r["service"], r["version"])
        if cpe:
            vulns = CVEAggregator().fetch_cve_by_cpe(cpe)
            print(r, vulns)

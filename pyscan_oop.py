#!/usr/bin/env python3
# pyscan_oop.py — OOP nmap-like async port scanner
from __future__ import annotations
import asyncio, argparse, ipaddress, ssl, json, time, random, datetime, socket
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Iterable

# ---------- Domain Models ----------
@dataclass
class ScanConfig:
    targets: List[str]
    ports: List[int]
    concurrency: int = 200
    timeout: float = 1.2
    jitter: float = 0.0
    retries: int = 0
    html_out: str | None = None
    json_out: str | None = None

@dataclass
class PortResult:
    host: str
    port: int
    state: str                 # OPEN / CLOSED / FILTERED/TIMEOUT / ERROR(...)
    banner: str = ""
    latency_ms: int | None = None

# ---------- Helpers ----------
def parse_ports(pstr: str) -> List[int]:
    ports = set()
    for part in pstr.split(","):
        part = part.strip()
        if not part: continue
        if "-" in part:
            a,b = part.split("-",1)
            a,b = int(a), int(b)
            if a>b: a,b = b,a
            for p in range(a,b+1):
                if 1<=p<=65535: ports.add(p)
        else:
            p=int(part)
            if 1<=p<=65535: ports.add(p)
    return sorted(ports)

def ports_for_profile(name: str | None) -> List[int]:
    if not name: return list(range(1,1025))
    match name:
        case "quick":  return list(range(1,1025))
        case "web":    return [22,80,443,8080,8081,8000,8443,8888,9000]
        case "db":     return [1433,1521,27017,3306,5432,6379,11211]
        case "common": return [21,22,23,25,53,80,110,139,143,389,443,445,465,587,631,636,993,995,1433,1521,1723,1883,2049,2375,2376,25565,27017,3000,3306,3389,5432,5900,5985,5986,6379,7001,7002,8080,8081,8443,9000,9200,11211]
    return list(range(1,1025))

def expand_targets(target: str) -> List[str]:
    try:
        net = ipaddress.ip_network(target, strict=False)
        return [str(h) for h in net.hosts()]
    except ValueError:
        return [target]

# ---------- Scanner ----------
class AsyncPortScanner:
    def __init__(self, cfg: ScanConfig) -> None:
        self.cfg = cfg
        self._sem = asyncio.Semaphore(cfg.concurrency)

    async def scan_all(self) -> List[PortResult]:
        results: List[PortResult] = []
        for host in self.cfg.targets:
            host_results = await self._scan_host(host)
            results.extend(host_results)
        return results

    async def _scan_host(self, host: str) -> List[PortResult]:
        tasks = [asyncio.create_task(self._guarded_probe(host, p)) for p in self.cfg.ports]
        return sorted(await asyncio.gather(*tasks), key=lambda r: r.port)

    async def _guarded_probe(self, host: str, port: int) -> PortResult:
        async with self._sem:
            return await self._probe_tcp(host, port)

    async def _probe_tcp(self, host: str, port: int) -> PortResult:
        start = time.perf_counter()
        attempt = 0
        last_state = "CLOSED"
        banner = ""
        while attempt <= self.cfg.retries:
            if self.cfg.jitter > 0:
                await asyncio.sleep(random.uniform(0.0, self.cfg.jitter))
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self.cfg.timeout
                )
                last_state = "OPEN"
                if port in (443,8443,9443):
                    banner = await self._tls_info(host, port)
                else:
                    banner = await self._grab_banner(reader, writer, host, port)
                try:
                    writer.close(); await writer.wait_closed()
                except Exception:
                    pass
                break
            except asyncio.TimeoutError:
                last_state = "FILTERED/TIMEOUT"
            except ConnectionRefusedError:
                last_state = "CLOSED"; break
            except OSError as e:
                last_state = f"ERROR ({e})"; break
            except Exception as e:
                last_state = f"ERROR ({e})"; break
            attempt += 1

        latency = int((time.perf_counter()-start)*1000)
        return PortResult(host, port, last_state, banner.strip(), latency)

    async def _grab_banner(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, host: str, port: int) -> str:
        try:
            if port in (80,8080,8000,8888):
                req = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: pyScan/0.3\r\nConnection: close\r\n\r\n"
                writer.write(req.encode()); await writer.drain()
                data = await asyncio.wait_for(reader.read(400), timeout=self.cfg.timeout)
                return data.decode(errors="ignore")
            if port in (25,587):
                writer.write(b"EHLO example.com\r\n"); await writer.drain()
                data = await asyncio.wait_for(reader.read(200), timeout=self.cfg.timeout)
                return data.decode(errors="ignore")
            if port == 6379:
                writer.write(b"*1\r\n$4\r\nPING\r\n"); await writer.drain()
                data = await asyncio.wait_for(reader.read(120), timeout=self.cfg.timeout)
                return data.decode(errors="ignore")
            if port in (21,22,3306,27017):
                data = await asyncio.wait_for(reader.read(260), timeout=self.cfg.timeout)
                return data.decode(errors="ignore")
        except Exception:
            pass
        return ""

    async def _tls_info(self, host: str, port: int) -> str:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx, server_hostname=host),
                timeout=self.cfg.timeout
            )
            ss = writer.get_extra_info("ssl_object")
            cert = ss.getpeercert() if ss else None
            ver = ss.version() if ss else ""
            try:
                writer.close(); await writer.wait_closed()
            except Exception:
                pass
            subj = iss = exp = ""
            if cert:
                try:
                    subj = dict(x[0] for x in cert.get("subject",())).get("commonName","")
                    iss  = dict(x[0] for x in cert.get("issuer", ())).get("commonName","")
                    na   = cert.get("notAfter")
                    if na:
                        dt = datetime.datetime.strptime(na, "%b %d %H:%M:%S %Y %Z")
                        exp = f"expires_in={(dt - datetime.datetime.utcnow()).days}d"
                except Exception:
                    pass
            parts = [p for p in [f"TLS={ver}" if ver else "", f"CN={subj}" if subj else "", f"Issuer={iss}" if iss else "", exp] if p]
            return " | ".join(parts)
        except Exception:
            return ""

# ---------- Reporting ----------
class ReportWriter:
    @staticmethod
    def to_json(results: Iterable[PortResult], path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump([asdict(r) for r in results], f, indent=2)

    @staticmethod
    def to_html(results: Iterable[PortResult], path: str) -> None:
        rows = []
        for r in results:
            b = r.banner
            if len(b)>90: b = b[:90] + "..."
            rows.append(f"<tr><td>{r.host}</td><td>{r.port}</td><td>{r.state}</td><td>{r.latency_ms} ms</td><td><pre>{b}</pre></td></tr>")
        html = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>pyScan Report</title>
<style>
body{{font-family:system-ui,Arial,sans-serif;margin:24px}}
table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #ddd;padding:8px;vertical-align:top}}
th{{background:#f6f6f6;text-align:left}}
pre{{white-space:pre-wrap;margin:0}}
</style></head><body>
<h1>pyScan Report</h1>
<p>Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<table><thead><tr><th>Host</th><th>Port</th><th>State</th><th>Latency</th><th>Banner/TLS</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table></body></html>"""
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

# ---------- CLI ----------
def build_config_from_args() -> ScanConfig:
    ap = argparse.ArgumentParser(description="pyScan (OOP) — async port scanner (authorized use only)")
    ap.add_argument("target", help="Host or CIDR, e.g. 192.168.1.0/24 or scanme.nmap.org")
    ap.add_argument("-p","--ports", help="Ports like '80,443' or '1-1024' (ignored if --profile)")
    ap.add_argument("--profile", choices=["quick","web","db","common"], help="Port profile")
    ap.add_argument("-c","--concurrency", type=int, default=200)
    ap.add_argument("-t","--timeout", type=float, default=1.2)
    ap.add_argument("--jitter", type=float, default=0.0)
    ap.add_argument("--retries", type=int, default=0)
    ap.add_argument("--json", dest="json_out")
    ap.add_argument("--html", dest="html_out")
    args = ap.parse_args()

    targets = expand_targets(args.target)
    ports = ports_for_profile(args.profile) if args.profile else parse_ports(args.ports or "1-1024")
    return ScanConfig(targets=targets, ports=ports, concurrency=args.concurrency,
                      timeout=args.timeout, jitter=args.jitter, retries=args.retries,
                      html_out=args.html_out, json_out=args.json_out)

def main():
    cfg = build_config_from_args()
    print(f"[i] Targets={len(cfg.targets)} Ports={len(cfg.ports)} c={cfg.concurrency} t={cfg.timeout}")
    scanner = AsyncPortScanner(cfg)
    results = asyncio.run(scanner.scan_all())

    # kısa özet
    for host in cfg.targets:
        open_ports = [r.port for r in results if r.host==host and r.state=="OPEN"]
        print(f"[+] {host} open: {', '.join(map(str, open_ports)) or 'none'}")

    if cfg.json_out:
        ReportWriter.to_json(results, cfg.json_out); print(f"[+] JSON -> {cfg.json_out}")
    if cfg.html_out:
        ReportWriter.to_html(results, cfg.html_out); print(f"[+] HTML -> {cfg.html_out}")

if __name__ == "__main__":
    # Etik uyarı: Yalnızca yetkili hedeflerde kullanın.
    main()

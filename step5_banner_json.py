
import asyncio
import socket
import argparse
import json
import ssl
from datetime import datetime

async def grab_banner(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, host: str, port: int, timeout: float):
    banner = ""
    try:
        if port in (80, 8080, 8000):
            req = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            writer.write(req.encode())
            await writer.drain()
            banner = await asyncio.wait_for(reader.read(200), timeout=timeout)
        elif port in (443, 8443):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            r2, w2 = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx, server_hostname=host),
                timeout=timeout
            )
            cert = w2.get_extra_info("ssl_object").getpeercert()
            banner = json.dumps(cert)
            w2.close()
            await w2.wait_closed()
        else:
            banner = await asyncio.wait_for(reader.read(200), timeout=timeout)
    except Exception:
        pass
    return banner.decode(errors="ignore") if isinstance(banner, bytes) else str(banner)

async def check_port_async(host: str, port: int, timeout: float):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host=host, port=port),
            timeout=timeout
        )
        state = "OPEN"
        banner = await grab_banner(reader, writer, host, port, timeout)
        writer.close()
        await writer.wait_closed()
    except asyncio.TimeoutError:
        state, banner = "FILTERED/TIMEOUT", ""
    except ConnectionRefusedError:
        state, banner = "CLOSED", ""
    except OSError as e:
        state, banner = f"ERROR ({e})", ""
    except Exception as e:
        state, banner = f"ERROR ({e})", ""
    return {"port": port, "state": state, "banner": banner.strip()}

def parse_ports(pstr: str):
    ports = set()
    for part in pstr.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            a, b = int(a), int(b)
            for p in range(min(a,b), max(a,b)+1):
                if 1 <= p <= 65535:
                    ports.add(p)
        else:
            p = int(part)
            if 1 <= p <= 65535:
                ports.add(p)
    return sorted(ports)

async def scan(host: str, ports: list[int], concurrency: int, timeout: float):
    sem = asyncio.Semaphore(concurrency)
    results = []
    async def worker(p):
        async with sem:
            res = await check_port_async(host, p, timeout)
            results.append(res)
    await asyncio.gather(*(worker(p) for p in ports))
    return sorted(results, key=lambda x: x["port"])

def main():
    ap = argparse.ArgumentParser(description="Async port scanner with banner grabbing & JSON output")
    ap.add_argument("target", help="Target host/IP")
    ap.add_argument("-p", "--ports", default="22,80,443", help="Ports (e.g. 1-1024 or 80,443)")
    ap.add_argument("-c", "--concurrency", type=int, default=200, help="Concurrent scans")
    ap.add_argument("-t", "--timeout", type=float, default=1.5, help="Timeout seconds")
    ap.add_argument("--json", help="Save results to JSON file")
    args = ap.parse_args()

    ports = parse_ports(args.ports)
    print(f"Target: {args.target} | Ports: {len(ports)} | Concurrency={args.concurrency} | Timeout={args.timeout}")
    print(f"Started at: {datetime.now().strftime('%H:%M:%S')}")
    print("PORT\tSTATE\tBANNER")

    results = asyncio.run(scan(args.target, ports, args.concurrency, args.timeout))

    for r in results:
        banner_display = r["banner"][:40] + "..." if len(r["banner"]) > 40 else r["banner"]
        print(f"{r['port']}\t{r['state']}\t{banner_display}")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        print(f"\n[+] Results saved to {args.json}")

if __name__ == "__main__":
    main()


import asyncio
import socket
import argparse
from datetime import datetime

async def check_port_async(host: str, port: int, timeout: float) -> tuple[int, str]:
    """
    Tek bir TCP porta async bağlantı dener.
    """
    loop = asyncio.get_running_loop()
    fut = loop.create_future()

    def _done(state: str):
        if not fut.done():
            fut.set_result(state)

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host=host, port=port),
            timeout=timeout
        )
        _done("OPEN")
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
    except asyncio.TimeoutError:
        _done("FILTERED/TIMEOUT")
    except ConnectionRefusedError:
        _done("CLOSED")
    except OSError as e:
        _done(f"ERROR ({e})")
    except Exception as e:
        _done(f"ERROR ({e})")

    state = await fut
    return port, state

def parse_ports(pstr: str):
    ports = set()
    for part in pstr.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            a, b = int(a), int(b)
            if a > b: a, b = b, a
            for p in range(a, b + 1):
                if 1 <= p <= 65535: ports.add(p)
        else:
            p = int(part)
            if 1 <= p <= 65535: ports.add(p)
    return sorted(ports)

async def scan(host: str, ports: list[int], concurrency: int, timeout: float):
    sem = asyncio.Semaphore(concurrency)
    results: list[tuple[int, str]] = []

    async def worker(p: int):
        async with sem:
            port, state = await check_port_async(host, p, timeout)
            results.append((port, state))

    tasks = [asyncio.create_task(worker(p)) for p in ports]
    await asyncio.gather(*tasks)
    return sorted(results, key=lambda x: x[0])

def main():
    ap = argparse.ArgumentParser(description="Hızlı async port tarayıcı (izinli hedeflerde kullan)")
    ap.add_argument("target", help="Hedef IP/alan adı")
    ap.add_argument("-p", "--ports", default="1-1024", help="Port(lar) örn: 22,80,443 veya 1-1024")
    ap.add_argument("-c", "--concurrency", type=int, default=200, help="Aynı anda kaç bağlantı (default 200)")
    ap.add_argument("-t", "--timeout", type=float, default=1.0, help="Zaman aşımı sn (default 1.0)")
    args = ap.parse_args()

    ports = parse_ports(args.ports)
    print(f"Target: {args.target} | {len(ports)} ports | c={args.concurrency} | t={args.timeout}")
    print(f"Started at: {datetime.now().strftime('%H:%M:%S')}")
    print("PORT\tSTATE")

    results = asyncio.run(scan(args.target, ports, args.concurrency, args.timeout))
    for p, state in results:
        print(f"{p}\t{state}")

    print(f"Finished at: {datetime.now().strftime('%H:%M:%S')}")

if __name__ == "__main__":
    main()


import socket
import argparse
from datetime import datetime

def parse_ports(pstr: str):
    """
    '80' veya '22,80,443' veya '1-1024' gibi ifadeleri listeye çevirir.
    """
    ports = set()
    for part in pstr.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            a, b = int(a), int(b)
            if a > b:
                a, b = b, a
            for p in range(a, b+1):
                if 1 <= p <= 65535:
                    ports.add(p)
        else:
            p = int(part)
            if 1 <= p <= 65535:
                ports.add(p)
    return sorted(ports)

def check_port(host, port, timeout=1.5):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return "OPEN"
    except socket.timeout:
        return "FILTERED/TIMEOUT"
    except ConnectionRefusedError:
        return "CLOSED"
    except OSError as e:
        return f"ERROR ({e})"
    finally:
        s.close()

def main():
    parser = argparse.ArgumentParser(description="Basit port tarayıcı (yalnızca izinli hedeflerde kullan)")
    parser.add_argument("target", help="Hedef IP/alan adı (örn: 127.0.0.1 veya scanme.nmap.org)")
    parser.add_argument("-p", "--ports", default="22,80,443",
                        help="Port(lar): '80' veya '22,80,443' veya '1-1024'")
    parser.add_argument("-t", "--timeout", type=float, default=1.5, help="Zaman aşımı (saniye)")
    args = parser.parse_args()

    ports = parse_ports(args.ports)
    if not ports:
        print("Geçerli port verilmedi. Örn: -p 22,80,443 veya -p 1-1024")
        return

    print(f"Target: {args.target} | Ports: {ports[:20]}{'...' if len(ports)>20 else ''}")
    print(f"Started at: {datetime.now().strftime('%H:%M:%S')}")
    print("PORT\tSTATE")

    for p in ports:
        state = check_port(args.target, p, args.timeout)
        print(f"{p}\t{state}")

if __name__ == "__main__":
    main()


import socket
from datetime import datetime

target = "127.0.0.1"      
ports  = [22, 80, 443, 3306, 5432, 6379, 8000]  
timeout = 1.5

def check_port(host, port, timeout=1.5):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        state = "OPEN"
    except socket.timeout:
        state = "FILTERED/TIMEOUT"
    except ConnectionRefusedError:
        state = "CLOSED"
    except OSError as e:
        state = f"ERROR ({e})"
    finally:
        s.close()
    return state

print(f"Target: {target}  | Ports: {ports}")
print(f"Started at: {datetime.now().strftime('%H:%M:%S')}")
print("PORT\tSTATE")

for p in ports:
    state = check_port(target, p, timeout)
    print(f"{p}\t{state}")

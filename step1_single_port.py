
import socket


target = "127.0.0.1"   
port = 80              
timeout = 1.5          

print(f"Hedef: {target}  Port: {port}")


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(timeout)

try:
   
    sock.connect((target, port))
    print("Sonuç: OPEN (bağlantı kuruldu)")
except socket.timeout:
    print("Sonuç: FILTERED/TIMEOUT (cevap gelmedi)")
except ConnectionRefusedError:
    print("Sonuç: CLOSED (kapalı)")
except OSError as e:
    print(f"Sonuç: ERROR ({e})")
finally:
    sock.close()

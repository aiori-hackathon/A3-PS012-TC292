import socket
import time
import sys

def main() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", 53))
    print("t13: Firewall drop server ready (reads and discards all packets)", flush=True)
    while True:
        data, addr = sock.recvfrom(4096)

if __name__ == "__main__":
    main()

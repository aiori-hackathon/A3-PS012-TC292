import socket
import time
import threading
import sys
try:
    import dns.message
    import dns.query
    import dns.rcode
    import dns.name
except ImportError:
    print("dnspython required", file=sys.stderr)
    sys.exit(1)

AUTHZONE_IP = "172.28.0.10"
DELAY = 1.5

def handle_query(data: bytes, addr: tuple, sock: socket.socket) -> None:
    try:
        time.sleep(DELAY)
        request = dns.message.from_wire(data)
        if request.question:
            q = request.question[0]
            probe_zone = dns.name.from_text("probe.lab.test.")
            if q.name.is_subdomain(probe_zone):
                response = dns.query.udp(request, AUTHZONE_IP, timeout=2.0)
                sock.sendto(response.to_wire(), addr)
                return
        response = dns.message.make_response(request)
        response.set_rcode(dns.rcode.REFUSED)
        sock.sendto(response.to_wire(), addr)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr, flush=True)

def main() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", 53))
    print(f"t18: High-latency server ready ({DELAY}s delay)", flush=True)
    while True:
        data, addr = sock.recvfrom(4096)
        threading.Thread(target=handle_query, args=(data, addr, sock), daemon=True).start()

if __name__ == "__main__":
    main()

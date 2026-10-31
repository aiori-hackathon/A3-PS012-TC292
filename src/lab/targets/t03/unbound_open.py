import socket
import threading
import sys
try:
    import dns.message
    import dns.query
    import dns.rcode
    import dns.flags
    import dns.name
except ImportError:
    print("dnspython required", file=sys.stderr)
    sys.exit(1)

AUTHZONE_IP = "172.28.0.10"
PROBE_ZONE = dns.name.from_text("probe.lab.test.")

def handle_query(data: bytes, addr: tuple, sock: socket.socket) -> None:
    try:
        request = dns.message.from_wire(data)
        if request.question:
            q = request.question[0]
            if q.name.is_subdomain(PROBE_ZONE):
                response = dns.query.udp(request, AUTHZONE_IP, timeout=2.0)
                response.flags &= ~dns.flags.AA
                response.flags |= dns.flags.RA | (request.flags & dns.flags.RD)
                sock.sendto(response.to_wire(), addr)
                return
        response = dns.message.make_response(request)
        response.flags |= dns.flags.RA
        response.set_rcode(dns.rcode.NXDOMAIN)
        sock.sendto(response.to_wire(), addr)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr, flush=True)

def main() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", 53))
    print("t03: Unbound-like open recursive server ready", flush=True)
    while True:
        data, addr = sock.recvfrom(4096)
        threading.Thread(target=handle_query, args=(data, addr, sock), daemon=True).start()

if __name__ == "__main__":
    main()

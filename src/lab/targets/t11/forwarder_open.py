import socket
import threading
import sys
try:
    import dns.message
    import dns.query
    import dns.rcode
    import dns.flags
except ImportError:
    print("dnspython required", file=sys.stderr)
    sys.exit(1)

UPSTREAM_IP = "172.28.0.103"

def handle_query(data: bytes, addr: tuple, sock: socket.socket) -> None:
    try:
        request = dns.message.from_wire(data)
        response = dns.query.udp(request, UPSTREAM_IP, timeout=2.0)
        sock.sendto(response.to_wire(), addr)
    except Exception as e:
        try:
            request = dns.message.from_wire(data)
            response = dns.message.make_response(request)
            response.set_rcode(dns.rcode.SERVFAIL)
            sock.sendto(response.to_wire(), addr)
        except Exception:
            pass

def main() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", 53))
    print("t11: Forwarder to open upstream ready", flush=True)
    while True:
        data, addr = sock.recvfrom(4096)
        threading.Thread(target=handle_query, args=(data, addr, sock), daemon=True).start()

if __name__ == "__main__":
    main()

import socket
import threading
import sys
try:
    import dns.message
    import dns.query
    import dns.rcode
except ImportError:
    print("dnspython required", file=sys.stderr)
    sys.exit(1)

def handle_query(data: bytes, addr: tuple, sock: socket.socket) -> None:
    try:
        request = dns.message.from_wire(data)
        if not request.question:
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
    print("t02: closed resolver ready (no authoritative zones)", flush=True)
    while True:
        data, addr = sock.recvfrom(4096)
        threading.Thread(target=handle_query, args=(data, addr, sock), daemon=True).start()

if __name__ == "__main__":
    main()

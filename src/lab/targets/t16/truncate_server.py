import socket
import struct
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

def resolve_upstream(request: dns.message.Message) -> dns.message.Message:
    if request.question:
        q = request.question[0]
        probe_zone = dns.name.from_text("probe.lab.test.")
        if q.name.is_subdomain(probe_zone):
            return dns.query.udp(request, AUTHZONE_IP, timeout=2.0)
    response = dns.message.make_response(request)
    response.set_rcode(dns.rcode.REFUSED)
    return response

def handle_udp(sock: socket.socket) -> None:
    while True:
        try:
            data, addr = sock.recvfrom(4096)
            request = dns.message.from_wire(data)
            response = dns.message.make_response(request)
            response.flags |= dns.flags.TC
            response.set_rcode(dns.rcode.NOERROR)
            sock.sendto(response.to_wire(), addr)
        except Exception as e:
            print(f"UDP error: {e}", file=sys.stderr, flush=True)

def handle_tcp_client(conn: socket.socket, addr: tuple) -> None:
    try:
        length_data = conn.recv(2)
        if len(length_data) < 2:
            return
        length = struct.unpack("!H", length_data)[0]
        data = b""
        while len(data) < length:
            chunk = conn.recv(length - len(data))
            if not chunk:
                return
            data += chunk
        request = dns.message.from_wire(data)
        response = resolve_upstream(request)
        wire = response.to_wire()
        conn.sendall(struct.pack("!H", len(wire)) + wire)
    except Exception as e:
        print(f"TCP error: {e}", file=sys.stderr, flush=True)
    finally:
        conn.close()

def main() -> None:
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp_sock.bind(("0.0.0.0", 53))

    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_sock.bind(("0.0.0.0", 53))
    tcp_sock.listen(16)

    print("t16: TCP-truncate server ready", flush=True)
    udp_thread = threading.Thread(target=handle_udp, args=(udp_sock,), daemon=True)
    udp_thread.start()

    while True:
        conn, addr = tcp_sock.accept()
        threading.Thread(target=handle_tcp_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    main()

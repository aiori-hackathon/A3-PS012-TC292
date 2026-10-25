import socket
import struct
import threading
import sys
try:
    import dns.message
    import dns.query
    import dns.rcode
    import dns.flags
    import dns.rdatatype
    import dns.name
    import dns.rrset
    import dns.rdata
except ImportError:
    print("dnspython required", file=sys.stderr)
    sys.exit(1)

MAX_QUERIES = 5
query_count = 0
count_lock = threading.Lock()
AUTHZONE_IP = "172.28.0.10"

def handle_query(data: bytes, addr: tuple, sock: socket.socket) -> None:
    global query_count
    with count_lock:
        query_count += 1
        current = query_count
    if current > MAX_QUERIES:
        return
    try:
        request = dns.message.from_wire(data)
        if request.question:
            q = request.question[0]
            qname = q.name
            probe_zone = dns.name.from_text("probe.lab.test.")
            if qname.is_subdomain(probe_zone):
                upstream_resp = dns.query.udp(request, AUTHZONE_IP, timeout=2.0)
                sock.sendto(upstream_resp.to_wire(), addr)
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
    print(f"t15: Rate-limited server ready (max {MAX_QUERIES} queries)", flush=True)
    while True:
        data, addr = sock.recvfrom(4096)
        threading.Thread(target=handle_query, args=(data, addr, sock), daemon=True).start()

if __name__ == "__main__":
    main()

import socket
import struct
import threading
import sys
import time
from collections import deque
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
WINDOW_SECONDS = 5.0
query_times: deque[float] = deque()
count_lock = threading.Lock()
AUTHZONE_IP = "172.28.0.10"

def handle_query(data: bytes, addr: tuple, sock: socket.socket) -> None:
    with count_lock:
        now = time.monotonic()
        while query_times and now - query_times[0] >= WINDOW_SECONDS:
            query_times.popleft()
        if len(query_times) >= MAX_QUERIES:
            return
        query_times.append(now)
    try:
        request = dns.message.from_wire(data)
        if request.question:
            q = request.question[0]
            qname = q.name
            probe_zone = dns.name.from_text("probe.lab.test.")
            if qname.is_subdomain(probe_zone):
                upstream_resp = dns.query.udp(request, AUTHZONE_IP, timeout=2.0)
                upstream_resp.flags &= ~dns.flags.AA
                upstream_resp.flags |= dns.flags.RA | (request.flags & dns.flags.RD)
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
    print(
        f"t15: Rate-limited server ready ({MAX_QUERIES} queries per "
        f"{WINDOW_SECONDS:g}s)",
        flush=True,
    )
    while True:
        data, addr = sock.recvfrom(4096)
        threading.Thread(target=handle_query, args=(data, addr, sock), daemon=True).start()

if __name__ == "__main__":
    main()

import socket
import hashlib
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
DROP_RATE = 0.30

# Deterministic transient loss: the FIRST packet for a qname is dropped iff
# hash(qname) falls under DROP_RATE; any later repeat of the same qname is
# always forwarded, so a UDP retry recovers. Ground truth stays Recursive
# for every seed once the scanner uses its configured udp_retries.
_seen_qnames: set[bytes] = set()


def _should_drop_first_attempt(qname_wire: bytes) -> bool:
    sample = int.from_bytes(
        hashlib.sha256(qname_wire).digest()[:8], "big"
    ) / 2**64
    return sample < DROP_RATE


def handle_query(data: bytes, addr: tuple, sock: socket.socket) -> None:
    try:
        request = dns.message.from_wire(data)
        if request.question:
            q = request.question[0]
            probe_zone = dns.name.from_text("probe.lab.test.")
            if q.name.is_subdomain(probe_zone):
                qname_wire = q.name.to_wire()
                if qname_wire not in _seen_qnames:
                    _seen_qnames.add(qname_wire)
                    if _should_drop_first_attempt(qname_wire):
                        return
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
    print(f"t19: Packet-loss server ready ({int(DROP_RATE*100)}% drop)", flush=True)
    while True:
        data, addr = sock.recvfrom(4096)
        threading.Thread(target=handle_query, args=(data, addr, sock), daemon=True).start()

if __name__ == "__main__":
    main()

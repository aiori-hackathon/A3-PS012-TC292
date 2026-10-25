import socket
import sys
try:
    import dns.message
    import dns.rcode
    import dns.flags
    import dns.rdatatype
    import dns.rrset
    import dns.rdata
    import dns.rdataclass
except ImportError:
    print("dnspython required", file=sys.stderr)
    sys.exit(1)

FAKE_IP = "198.51.100.1"

def handle(data: bytes) -> bytes:
    request = dns.message.from_wire(data)
    response = dns.message.make_response(request)
    response.flags |= dns.flags.RA
    if request.question:
        q = request.question[0]
        rrset = dns.rrset.RRset(q.name, dns.rdataclass.IN, dns.rdatatype.A)
        rrset.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, FAKE_IP))
        rrset.update_ttl(60)
        response.answer.append(rrset)
        response.set_rcode(dns.rcode.NOERROR)
    return response.to_wire()

def main() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", 53))
    print("t17: Lying resolver ready (RA=1, fake answers, no upstream)", flush=True)
    while True:
        try:
            data, addr = sock.recvfrom(4096)
            sock.sendto(handle(data), addr)
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr, flush=True)

if __name__ == "__main__":
    main()

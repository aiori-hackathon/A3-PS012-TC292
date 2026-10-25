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
    import dns.rdataclass
    import dns.name
    import dns.rrset
    import dns.rdata
except ImportError:
    print("dnspython required", file=sys.stderr)
    sys.exit(1)

AUTHZONE_IP = "172.28.0.10"
OWN_ZONE = dns.name.from_text("owned.t01.lab.test.")
PROBE_ZONE = dns.name.from_text("probe.lab.test.")

def build_auth_response(request: dns.message.Message) -> dns.message.Message:
    response = dns.message.make_response(request)
    response.flags |= dns.flags.AA
    q = request.question[0]
    if q.rdtype == dns.rdatatype.SOA:
        soa = "ns.owned.t01.lab.test. admin.owned.t01.lab.test. 2026101601 3600 900 604800 86400"
        rrset = dns.rrset.RRset(OWN_ZONE, dns.rdataclass.IN, dns.rdatatype.SOA)
        rrset.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.SOA, soa))
        rrset.update_ttl(3600)
        response.answer.append(rrset)
    elif q.rdtype == dns.rdatatype.A:
        if str(q.name) in ("ns.owned.t01.lab.test.", "www.owned.t01.lab.test."):
            rrset = dns.rrset.RRset(q.name, dns.rdataclass.IN, dns.rdatatype.A)
            rrset.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, "172.28.0.101"))
            rrset.update_ttl(3600)
            response.answer.append(rrset)
    return response

def handle_query(data: bytes, addr: tuple, sock: socket.socket) -> None:
    try:
        request = dns.message.from_wire(data)
        if not request.question:
            return
        q = request.question[0]
        if q.name == OWN_ZONE or q.name.is_subdomain(OWN_ZONE):
            response = build_auth_response(request)
            sock.sendto(response.to_wire(), addr)
            return
        if q.name.is_subdomain(PROBE_ZONE):
            response = dns.query.udp(request, AUTHZONE_IP, timeout=2.0)
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
    print("t01: BIND-like open recursive server ready", flush=True)
    while True:
        data, addr = sock.recvfrom(4096)
        threading.Thread(target=handle_query, args=(data, addr, sock), daemon=True).start()

if __name__ == "__main__":
    main()

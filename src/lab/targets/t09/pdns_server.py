import socket
import sys
try:
    import dns.message
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

OWN_ZONE = dns.name.from_text("owned.t09.lab.test.")

def build_response(request: dns.message.Message) -> dns.message.Message:
    response = dns.message.make_response(request)
    if not request.question:
        response.set_rcode(dns.rcode.REFUSED)
        return response
    q = request.question[0]
    if q.name == OWN_ZONE or q.name.is_subdomain(OWN_ZONE):
        response.flags |= dns.flags.AA
        if q.rdtype == dns.rdatatype.SOA:
            soa = "ns.owned.t09.lab.test. admin.owned.t09.lab.test. 2026101601 3600 900 604800 86400"
            rrset = dns.rrset.RRset(OWN_ZONE, dns.rdataclass.IN, dns.rdatatype.SOA)
            rrset.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.SOA, soa))
            rrset.update_ttl(3600)
            response.answer.append(rrset)
        elif q.rdtype == dns.rdatatype.A:
            if str(q.name) in ("ns.owned.t09.lab.test.", "www.owned.t09.lab.test."):
                rrset = dns.rrset.RRset(q.name, dns.rdataclass.IN, dns.rdatatype.A)
                rrset.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, "172.28.0.109"))
                rrset.update_ttl(3600)
                response.answer.append(rrset)
            else:
                response.set_rcode(dns.rcode.NXDOMAIN)
    else:
        response.set_rcode(dns.rcode.REFUSED)
    return response

def main() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", 53))
    print("t09: PowerDNS-like auth server ready", flush=True)
    while True:
        try:
            data, addr = sock.recvfrom(4096)
            request = dns.message.from_wire(data)
            response = build_response(request)
            sock.sendto(response.to_wire(), addr)
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr, flush=True)

if __name__ == "__main__":
    main()

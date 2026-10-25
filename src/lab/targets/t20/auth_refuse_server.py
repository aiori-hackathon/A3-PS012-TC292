import socket
import struct
import threading
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

OWN_ZONE = dns.name.from_text("owned.t20.lab.test.")

SOA_MNAME = "ns.owned.t20.lab.test."
SOA_RNAME = "admin.owned.t20.lab.test."
SOA_SERIAL = 2026101601
SOA_REFRESH = 3600
SOA_RETRY = 900
SOA_EXPIRE = 604800
SOA_MINIMUM = 86400

RECORDS = {
    "ns.owned.t20.lab.test.": "172.28.0.120",
    "www.owned.t20.lab.test.": "172.28.0.120",
}

def build_response(request: dns.message.Message) -> dns.message.Message:
    response = dns.message.make_response(request)
    if not request.question:
        response.set_rcode(dns.rcode.REFUSED)
        return response

    q = request.question[0]
    qname = q.name
    qtype = q.rdtype

    if qname == OWN_ZONE or qname.is_subdomain(OWN_ZONE):
        response.flags |= dns.flags.AA
        if qtype == dns.rdatatype.SOA or (qtype == dns.rdatatype.ANY):
            soa_text = f"{SOA_MNAME} {SOA_RNAME} {SOA_SERIAL} {SOA_REFRESH} {SOA_RETRY} {SOA_EXPIRE} {SOA_MINIMUM}"
            rrset = dns.rrset.RRset(OWN_ZONE, dns.rdataclass.IN, dns.rdatatype.SOA)
            rrset.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.SOA, soa_text))
            rrset.update_ttl(3600)
            response.answer.append(rrset)
        elif qtype == dns.rdatatype.A:
            key = str(qname)
            if key in RECORDS:
                rrset = dns.rrset.RRset(qname, dns.rdataclass.IN, dns.rdatatype.A)
                rrset.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, RECORDS[key]))
                rrset.update_ttl(3600)
                response.answer.append(rrset)
            else:
                response.set_rcode(dns.rcode.NXDOMAIN)
        elif qtype == dns.rdatatype.NS:
            rrset = dns.rrset.RRset(OWN_ZONE, dns.rdataclass.IN, dns.rdatatype.NS)
            rrset.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.NS, SOA_MNAME))
            rrset.update_ttl(3600)
            response.answer.append(rrset)
        else:
            response.set_rcode(dns.rcode.NOERROR)
    else:
        response.set_rcode(dns.rcode.REFUSED)
    return response

def handle_udp(sock: socket.socket) -> None:
    while True:
        try:
            data, addr = sock.recvfrom(4096)
            request = dns.message.from_wire(data)
            response = build_response(request)
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
        response = build_response(request)
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

    print("t20: Auth-refuse-else server ready", flush=True)
    udp_thread = threading.Thread(target=handle_udp, args=(udp_sock,), daemon=True)
    udp_thread.start()

    while True:
        conn, addr = tcp_sock.accept()
        threading.Thread(target=handle_tcp_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    main()

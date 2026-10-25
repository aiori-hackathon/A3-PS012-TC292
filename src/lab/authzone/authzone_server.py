import json
import socket
import struct
import threading
import time
import os
import sys

try:
    import dns.message
    import dns.rdatatype
    import dns.name
    import dns.rrset
    import dns.rdata
    import dns.flags
    import dns.rcode
except ImportError:
    print("dnspython required: pip install dnspython", file=sys.stderr)
    sys.exit(1)

ZONE = dns.name.from_text("probe.lab.test.")
ANSWER_IP = "192.0.2.1"
LOG_PATH = os.environ.get("AUTHZONE_LOG", "/var/log/authzone/queries.jsonl")
LISTEN_ADDR = "0.0.0.0"
LISTEN_PORT = 53

log_lock = threading.Lock()


def log_query(qname: str, qtype: str, src_ip: str) -> None:
    nonce = qname.split(".")[0] if "." in qname else qname
    entry = {
        "ts": time.time(),
        "qname": qname,
        "qtype": qtype,
        "src_ip": src_ip,
        "nonce": nonce,
    }
    with log_lock:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, "a") as f:
            f.write(json.dumps(entry) + "\n")
            f.flush()


def build_response(request: dns.message.Message) -> dns.message.Message:
    response = dns.message.make_response(request)
    response.flags |= dns.flags.AA
    response.flags |= dns.flags.QR
    response.flags &= ~dns.flags.RD

    if request.question:
        q = request.question[0]
        qname = q.name
        if qname.is_subdomain(ZONE):
            rrset = dns.rrset.RRset(qname, dns.rdataclass.IN, dns.rdatatype.A)
            rrset.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, ANSWER_IP))
            rrset.update_ttl(60)
            response.answer.append(rrset)
            response.set_rcode(dns.rcode.NOERROR)
        else:
            response.set_rcode(dns.rcode.REFUSED)

    return response


def handle_udp(sock: socket.socket) -> None:
    while True:
        try:
            data, addr = sock.recvfrom(4096)
            request = dns.message.from_wire(data)
            if request.question:
                q = request.question[0]
                log_query(str(q.name), dns.rdatatype.to_text(q.rdtype), addr[0])
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
        if request.question:
            q = request.question[0]
            log_query(str(q.name), dns.rdatatype.to_text(q.rdtype), addr[0])
        response = build_response(request)
        wire = response.to_wire()
        conn.sendall(struct.pack("!H", len(wire)) + wire)
    except Exception as e:
        print(f"TCP error: {e}", file=sys.stderr, flush=True)
    finally:
        conn.close()


def serve_tcp(sock: socket.socket) -> None:
    sock.listen(16)
    while True:
        conn, addr = sock.accept()
        threading.Thread(target=handle_tcp_client, args=(conn, addr), daemon=True).start()


def main() -> None:
    print(f"Authzone server starting on {LISTEN_ADDR}:{LISTEN_PORT}", flush=True)
    print(f"Zone: {ZONE} -> {ANSWER_IP}", flush=True)
    print(f"Log: {LOG_PATH}", flush=True)

    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp_sock.bind((LISTEN_ADDR, LISTEN_PORT))

    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_sock.bind((LISTEN_ADDR, LISTEN_PORT))

    udp_thread = threading.Thread(target=handle_udp, args=(udp_sock,), daemon=True)
    tcp_thread = threading.Thread(target=serve_tcp, args=(tcp_sock,), daemon=True)
    udp_thread.start()
    tcp_thread.start()

    print("Authzone server ready.", flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("Shutting down.", flush=True)


if __name__ == "__main__":
    main()

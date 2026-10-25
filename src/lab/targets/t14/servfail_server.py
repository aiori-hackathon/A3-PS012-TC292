import socket
import struct
import sys
try:
    import dns.message
    import dns.rcode
    import dns.flags
except ImportError:
    print("dnspython required", file=sys.stderr)
    sys.exit(1)

def make_servfail(request: dns.message.Message) -> dns.message.Message:
    response = dns.message.make_response(request)
    response.set_rcode(dns.rcode.SERVFAIL)
    return response

def main() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", 53))
    print("t14: SERVFAIL server ready", flush=True)
    while True:
        try:
            data, addr = sock.recvfrom(4096)
            request = dns.message.from_wire(data)
            response = make_servfail(request)
            sock.sendto(response.to_wire(), addr)
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr, flush=True)

if __name__ == "__main__":
    main()

import socket
import struct

def build_dns_query(domain):
    """Build a DNS query packet."""
    transaction_id = struct.pack('!H', 1234)
    flags = struct.pack('!H', 0x0100)
    qdcount = struct.pack('!H', 1)
    ancount = struct.pack('!H', 0)
    nscount = struct.pack('!H', 0)
    arcount = struct.pack('!H', 0)

    question = b''
    for part in domain.split('.'):
        length = len(part)
        question += struct.pack('!B', length) + part.encode()
    question += b'\x00'

    qtype = struct.pack('!H', 1)
    qclass = struct.pack('!H', 1)

    return transaction_id + flags + qdcount + ancount + nscount + arcount + question + qtype + qclass

def parse_dns_response(response):
    """Parse the DNS response to extract the IP address."""
    pos = 12

    while pos < len(response) and response[pos] != 0:
        if response[pos] >= 192:
            pos += 2
            break
        pos += response[pos] + 1

    pos += 1 + 4
    pos += 10

    rdlength = struct.unpack('!H', response[pos:pos+2])[0]
    pos += 2

    if rdlength == 4 and pos + 4 <= len(response):
        ip = '.'.join(str(b) for b in response[pos:pos+4])
        return ip
    return None

def resolve_domain(domain, dns_server="1.1.1.1", dns_port=53):
    """Resolve a domain name to IP address using a specified DNS server."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(10)

    try:
        query = build_dns_query(domain)
        sock.sendto(query, (dns_server, dns_port))

        response, _ = sock.recvfrom(1024)

        ip = parse_dns_response(response)

        return ip if ip is not None else "Failed to parse response"

    except socket.timeout:
        return "Query timed out"
    except Exception as e:
        return f"Error: {str(e)}"
    finally:
        sock.close()

def main():
    """Main function to resolve a single domain."""
    domain = input("Enter domain name: ").strip()

    if not domain:
        print("No domain provided. Exiting.")
        return

    ip = resolve_domain(domain)
    print(f"IP address of {domain}: {ip}")

if __name__ == "__main__":
    main()
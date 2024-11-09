import socket
import struct

def build_dns_query(domain):
    """Build a DNS query packet."""
    # Transaction ID
    transaction_id = struct.pack('!H', 1234)

    # Flags (Standard query)
    flags = struct.pack('!H', 0x0100)

    # Counts
    qdcount = struct.pack('!H', 1)  # One question
    ancount = struct.pack('!H', 0)  # No answers
    nscount = struct.pack('!H', 0)  # No authority records
    arcount = struct.pack('!H', 0)  # No additional records

    # Build question section
    question = b''
    for part in domain.split('.'):
        length = len(part)
        question += struct.pack('!B', length) + part.encode()
    question += b'\x00'  # Terminating null byte

    # Query type (A record) and class (IN)
    qtype = struct.pack('!H', 1)    # A record
    qclass = struct.pack('!H', 1)   # IN class

    return transaction_id + flags + qdcount + ancount + nscount + arcount + question + qtype + qclass

def parse_dns_response(response):
    """Parse the DNS response to extract the IP address."""
    # Skip header and question section
    # This is a simplified parser that assumes we're getting an A record
    pos = 12  # Skip fixed header

    # Skip the question name
    while pos < len(response) and response[pos] != 0:
        if response[pos] >= 192:  # Compression pointer
            pos += 2
            break
        pos += response[pos] + 1
    if pos < len(response):
        pos += 1  # Skip the null byte

    if pos + 4 >= len(response):
        return None

    pos += 4  # Skip qtype and qclass

    # Skip answer name, type, class, and TTL
    if pos + 10 >= len(response):
        return None

    pos += 10

    # Read data length
    if pos + 2 >= len(response):
        return None

    rdlength = struct.unpack('!H', response[pos:pos+2])[0]
    pos += 2

    # Read IP address
    if rdlength == 4 and pos + 4 <= len(response):  # IPv4 address
        ip = '.'.join(str(b) for b in response[pos:pos+4])
        return ip
    return None

def resolve_domain(domain, dns_server="1.1.1.1", dns_port=53):
    """Resolve a domain name to IP address using a specified DNS server."""
    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(10)  # Increased timeout to 10 seconds

    try:
        # Build and send query
        query = build_dns_query(domain)
        sock.sendto(query, (dns_server, dns_port))

        # Receive response
        response, _ = sock.recvfrom(1024)  # Increased buffer size

        # Parse response
        ip = parse_dns_response(response)
        if ip is None:
            return "Failed to parse response"
        return ip

    except socket.timeout:
        return "Query timed out"
    except Exception as e:
        return f"Error: {str(e)}"
    finally:
        sock.close()

def main():
    """Main function with interactive input."""
    print("DNS Resolver - Enter domain names to resolve")
    print("Example: google.com")

    while True:
        try:
            domain = input("\nEnter domain name: ").strip()
            if not domain:
                continue

            print(f"Resolving {domain}...")
            ip = resolve_domain(domain)
            print(f"IP address of {domain}: {ip}")

        except KeyboardInterrupt:
            print("\nExiting...")
            break
        except Exception as e:
            print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()

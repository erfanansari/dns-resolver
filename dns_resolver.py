import socket
import struct
import threading

class DNSResolver:
    def __init__(self, max_threads=3):
        self.semaphore = threading.Semaphore(max_threads)
        self.results = {}
        self.lock = threading.Lock()

    def build_dns_query(self, domain):
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

    def parse_dns_response(self, response):
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

    def resolve_domain(self, domain):
        """Resolve a domain name to IP address using a specified DNS server."""
        self.semaphore.acquire()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(10)

            try:
                query = self.build_dns_query(domain)
                sock.sendto(query, ("1.1.1.1", 53))

                response, _ = sock.recvfrom(1024)

                ip = self.parse_dns_response(response)

                with self.lock:
                    self.results[domain] = ip if ip is not None else "Failed to parse response"

            except socket.timeout:
                with self.lock:
                    self.results[domain] = "Query timed out"
            except Exception as e:
                with self.lock:
                    self.results[domain] = f"Error: {str(e)}"
            finally:
                sock.close()
        finally:
            self.semaphore.release()

def main():
    """Main function to resolve multiple domains using semaphore."""
    resolver = DNSResolver()
    threads = []

    # Get domain inputs
    domains = [input(f"Enter domain {i+1}: ").strip() for i in range(3)]

    # Create and start threads for each domain
    for domain in domains:
        thread = threading.Thread(target=resolver.resolve_domain, args=(domain,))
        threads.append(thread)
        thread.start()

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    # Print results
    for domain in domains:
        print(f"IP address of {domain}: {resolver.results.get(domain, 'Not resolved')}")

if __name__ == "__main__":
    main()
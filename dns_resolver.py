import socket
import struct
import threading

class DNSResolver:
    def __init__(self):
        # Allow up to 3 simultaneous DNS lookups
        self.semaphore = threading.Semaphore(3)
        # Store results for each domain
        self.results = {}
        # Lock for thread-safe writing to results
        self.lock = threading.Lock()

    def build_dns_query(self, domain):
        # 1. Create DNS header (12 bytes total)
        header = b''
        header += struct.pack('!H', 1234)    # Transaction ID
        header += struct.pack('!H', 0x0100)  # Flags (standard query)
        header += struct.pack('!H', 1)       # Questions count
        header += struct.pack('!H', 0)       # Answer count
        header += struct.pack('!H', 0)       # Authority count
        header += struct.pack('!H', 0)       # Additional count

        # 2. Create DNS question
        question = b''
        # Convert domain (e.g., "google.com" to "\x06google\x03com\x00")
        for part in domain.split('.'):
            question += struct.pack('!B', len(part)) + part.encode()
        question += b'\x00'  # End of domain name

        # 3. Add query type (A record) and class (IN)
        question += struct.pack('!H', 1)  # Type: A record (IPv4)
        question += struct.pack('!H', 1)  # Class: IN (Internet)

        # 4. Combine all parts
        return header + question

    def parse_dns_response(self, response):
        # Skip first 12 bytes (DNS header)
        position = 12

        # Skip the question section
        while position < len(response):
            # Check for DNS compression
            if response[position] >= 192:  # Compression marker
                position += 2
                break
            # Regular domain name part
            if response[position] == 0:    # End of domain name
                position += 1
                break
            position += response[position] + 1

        # Skip query type and class
        position += 4

        # Skip to the IP address location
        position += 10

        # Get length of IP address data
        rdlength = struct.unpack('!H', response[position:position+2])[0]
        position += 2

        # Extract IP address if it's IPv4 (4 bytes)
        if rdlength == 4 and position + 4 <= len(response):
            return '.'.join(str(b) for b in response[position:position+4])
        return None

    def resolve_domain(self, domain):
        # Wait for available thread slot
        self.semaphore.acquire()
        try:
            # Create UDP socket for DNS query
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(10)  # Wait max 10 seconds for response

            try:
                # Send query to Cloudflare's DNS (1.1.1.1)
                query = self.build_dns_query(domain)
                sock.sendto(query, ("1.1.1.1", 53))

                # Get response
                response, _ = sock.recvfrom(1024)
                ip = self.parse_dns_response(response)

                # Store result safely
                with self.lock:
                    self.results[domain] = ip if ip else "Failed to parse response"

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
    # Create resolver
    resolver = DNSResolver()
    threads = []

    # Get three domain names from user
    domains = [input(f"Enter domain {i+1}: ").strip() for i in range(3)]

    # Start a thread for each domain
    for domain in domains:
        thread = threading.Thread(target=resolver.resolve_domain, args=(domain,))
        threads.append(thread)
        thread.start()

    # Wait for all lookups to complete
    for thread in threads:
        thread.join()

    # Show results
    for domain in domains:
        print(f"IP address of {domain} {resolver.results.get(domain, 'Not resolved')}")

if __name__ == "__main__":
    main()
# Simple DNS Resolver

A lightweight DNS resolver implemented in Python that performs DNS lookups using UDP sockets. This tool allows you to resolve domain names to their corresponding IP addresses using custom DNS servers.

## Features

- Pure Python implementation with no external dependencies
- Uses UDP sockets for DNS queries
- Supports custom DNS servers (default: Cloudflare's 1.1.1.1)
- Interactive command-line interface
- Proper DNS packet construction and parsing
- Error handling and timeout management

## Prerequisites

- Python 3.x
- No additional packages required (uses only standard library)

## Usage

Run the script:
```bash
python3 dns_resolver.py
```

The program will prompt you to enter domain names. Example session:
```
DNS Resolver - Enter domain names to resolve
Example: google.com

Enter domain name: google.com
Resolving google.com...
IP address of google.com: 142.250.XXX.XXX

Enter domain name: github.com
Resolving github.com...
IP address of github.com: 140.82.XXX.XXX
```

## How It Works

1. **DNS Query Construction**: The script builds a proper DNS query packet with:
   - Transaction ID
   - Query flags
   - Question section with the domain name
   - Type A record request
   - IN class specification

2. **UDP Communication**: Uses UDP sockets to:
   - Send the query to the specified DNS server
   - Receive the response
   - Handle timeouts and errors

3. **Response Parsing**: Parses the DNS response to:
   - Skip headers and question section
   - Handle compression pointers
   - Extract the IP address from the answer section

## Project Structure

```
dns-resolver/
├── README.md
├── LICENSE
└── dns_resolver.py
```

## Limitations

- Only supports A records (IPv4 addresses)
- Does not support recursive queries
- Basic DNS response parsing
- No caching mechanism


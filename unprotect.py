from dnslib import DNSRecord
import socket
import base64
import binascii
import re
import time

# IP address of the DNS server
dns_server = "35.239.239.183"

# Domain name and subdomain that I control
domain_name = "slay.services"
subdomain = "t"

# HTTP request to embed in DNS request, encoded
message = "curl --head google.com"
message_bytes = message.encode('ascii')
base64_bytes = base64.b64encode(message_bytes)
base64_message = base64_bytes.decode('ascii')

# DNS query with encoded data prepended to domain of request
query = DNSRecord.question(base64_message + "." + subdomain + "." + domain_name, "A")

# Send DNS query to DNS server
dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
dns_socket.settimeout(5)
dns_socket.sendto(query.pack(), (dns_server, 53))

# Response will be delivered in chunks from DNS server
chunks = ""

while True:
    # Receive the DNS response from the DNS server
    try:
        byteData, addr = dns_socket.recvfrom(4096) 
    except socket.timeout:
        break # times out after full response received

    # Parse DNS response
    try:
        msg = binascii.unhexlify(binascii.b2a_hex(byteData))
        msg = DNSRecord.parse(msg)
    except Exception as e:
        print(e)
        break

    # Retrieve encoded data prepended to domain in DNS response
    m = re.search(r'\n(\S+)\.m\.slay\.services', str(msg), re.MULTILINE)
    rcv_base64_message = m.group(1)
    rcv_base64_bytes = rcv_base64_message.encode('ascii')
    rcv_message_bytes = base64.b64decode(rcv_base64_bytes)
    rcv_message = rcv_message_bytes.decode('ascii')

    # Append decoded message to variable
    chunks+=rcv_message

# Print full response and closes socket connection
print(chunks)
dns_socket.close()

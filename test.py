from frame import *
import socket

# --- Send query and decode response ---
header = DNSHeader(0x1234, DNSHeader_Flags(False, 0, False, False, True, False, False, False, 0), 0, 0, 0, 0)
packet = DNSPacket(header)
packet.add_question(DNSQuestion("flerken.pl.eu.org", 1, 1))

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(5)
sock.sendto(bytes(packet), ("ns1.eu.org", 53))
response, _ = sock.recvfrom(512)
sock.close()

parsed = DNSPacket.from_bytes(response)
print(parsed)
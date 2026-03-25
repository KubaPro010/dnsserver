from protocol.frame import *
import socket
import traceback
import argparse
import hmac, hashlib
import random
import select
from lib.libcounter import Counter
import time

BUFFER_SIZE = 1232
EDNS_SECRET = random.randbytes(8)

parser = argparse.ArgumentParser()
parser.add_argument("primary", type=str)
parser.add_argument("primary_port", type=int, default=53, required=False)
parser.add_argument("host", type=str, default="0.0.0.0", required=False)
parser.add_argument("port", type=int, default=53, required=False)
parser.add_argument("rps", type=int, default=75, required=False)
args = parser.parse_args()

def query_dns(packet: DNSPacket, timeout: float = 2.0, force_tcp: bool = False) -> DNSPacket:
    server_host = args.primary
    port = args.primary_port
    packet.add_additional_rr(EDNSOptRecord(False, BUFFER_SIZE, []))
    if not force_tcp:
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.settimeout(timeout)
        try:
            udp.sendto(bytes(packet), (server_host, port))
            data, _ = udp.recvfrom(BUFFER_SIZE)
            response = DNSPacket.from_bytes(data)

            if not response.header.flags.tc: return response
        except Exception: pass
        finally: udp.close()

    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.settimeout(timeout)
    try:
        tcp.connect((server_host, port))
        msg = bytes(packet)
        tcp.sendall(struct.pack("!H", len(msg)) + msg)

        raw_len = tcp.recv(2)
        if len(raw_len) < 2: raise RuntimeError("Failed to read TCP response length")
        msg_len = int.from_bytes(raw_len, "big")

        data = b""
        while len(data) < msg_len:
            chunk = tcp.recv(msg_len - len(data))
            if not chunk: raise RuntimeError("Incomplete TCP response")
            data += chunk
        return DNSPacket.from_bytes(data)
    finally: tcp.close()

HOST = args.host
PORT = args.port
TCP_PORT = PORT
REQUESTS_PER_SECOND = args.rps

soa = None
soa_zone = None
soa_serial = 0
soa_refresh = 0
soa_retry = 0
soa_expire = 0
data_age = 0
records: dict[str, list[DNSAnswer]] = {}
raw_records: list[DNSAnswer] = []

def fetch_records():
    global soa, soa_serial, soa_refresh, soa_retry, soa_expire, data_age, records, soa_zone, raw_records
    if soa_serial != 0 and soa_zone:
        soa_packet = DNSPacket(DNSHeader(random.randint(0, 0xffff), DNSHeader_Flags(False, DNSOPCode.QUERY, False, False, False, False, False, False, DNSRCode.NOERROR)))
        soa_packet.add_question(DNSQuestion(soa_zone, DNSType.SOA, DNSClass.IN))
        soa_res = query_dns(soa_packet)
        for aw in soa_res.answers:
            if aw.type != DNSType.SOA: continue
            tokens = aw.rdata_decoded.split()
            params = {k: int(v) for k, v in (t.split("=") for t in tokens[2:])}
            if soa_serial == int(params["serial"]): return # We have the same serial
    
    packet = DNSPacket(DNSHeader(random.randint(0, 0xffff), DNSHeader_Flags(False, DNSOPCode.QUERY, False, False, False, False, False, False, DNSRCode.NOERROR)))
    packet.add_question(DNSQuestion(".", DNSType.AXFR, DNSClass.IN))
    res = query_dns(packet, force_tcp=True)
    if res.header.flags.rcode != DNSRCode.NOERROR: raise Exception
    data_age = time.monotonic()
    raw_records = res.answers
    for anwser in res.answers:
        match anwser.type: 
            case DNSType.SOA:
                soa = anwser
                soa_zone = anwser.name
                tokens = soa.rdata_decoded.split()
                params = {k: int(v) for k, v in (t.split("=") for t in tokens[2:])}
                soa_serial = int(params["serial"])
                soa_refresh = int(params["refresh"])
                soa_retry = int(params["retry"])
                soa_expire = int(params["expire"])
            case _:
                if (d := records.get(anwser.name)): records[anwser.name] = d + [anwser]
                else: records[anwser.name] = [anwser]

ip_counts: dict[bytes, Counter] = {}

class Transport(IntEnum):
    UDP = 0
    TCP = 1
UDP = Transport.UDP
TCP = Transport.TCP

def handle(packet: DNSPacket, client_ip: bytes, transport: IntEnum):
    out = DNSPacket(DNSHeader(
        packet.header.transaction_id,
        DNSHeader_Flags(True, DNSOPCode.QUERY, True, False, True, False, False, False, DNSRCode.NOERROR)
    ))
    if (c := ip_counts.get(client_ip)):
        c.beat()
        if c.get_rate() > REQUESTS_PER_SECOND:
            out.header.flags.rcode = DNSRCode.REFUSED
            return bytes(out)
    else: ip_counts[client_ip] = Counter()

    if packet.header.flags.qr: return
    if packet.header.flags.opcode != DNSOPCode.QUERY:
        print("Unhandled opcode:", packet.header.flags.opcode)
        return

    for question in packet.questions:
        out.add_question(question)
        for record in records[question.qname]:
            if record.type != question.qtype and record.type not in (DNSType.A, DNSType.AAAA) and question.qtype != DNSType.CNAME: continue
            if record.record_class != DNSClass.ANY and question.qclass != DNSClass.ANY and question.qclass == record.record_class: continue
            out.add_answer(record)
   
    max_size = BUFFER_SIZE
    edns_options = []
    for additional in packet.additional:
        if isinstance(additional, EDNSOptRecord):
            if max_size > additional.max_udp_size: max_size = additional.max_udp_size
            # print(additional)
            for option in additional.options:
                match option.code:
                    case EDNSOptionCode.COOKIE:
                        edns_options.append(EDNSOption(EDNSOptionCode.COOKIE, option.data + hmac.new(EDNS_SECRET, option.data + client_ip, hashlib.md5).digest()))
    out.add_additional_rr(EDNSOptRecord(False, max_size, edns_options))

    if len(out) > max_size: out.header.flags.tc = True

    return bytes(out)[:max_size]

def recv_tcp(conn: socket.socket) -> bytes | None:
    raw_len = conn.recv(2)
    if len(raw_len) < 2: return None
    msg_len = int.from_bytes(raw_len, "big")

    data = b""
    while len(data) < msg_len:
        chunk = conn.recv(msg_len - len(data))
        if not chunk: return None
        data += chunk
    return data

udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

udp.bind((HOST, PORT))
tcp.bind((HOST, TCP_PORT))
print(f"UDP listening on {HOST}:{PORT}")

tcp.listen(32)
print(f"TCP listening on {HOST}:{TCP_PORT}")

with udp, tcp:
    fetch_records()
    time_until_fetch = data_age + soa_refresh
    retried = False

    while True:
        try:
            readable, _, _ = select.select([udp, tcp], [], [], 10)
            for sock in readable:
                if sock is udp:
                    data, addr = udp.recvfrom(BUFFER_SIZE)
                    if data:
                        out = handle(DNSPacket.from_bytes(data), socket.inet_aton(addr[0]), UDP)
                        if out: udp.sendto(out, addr)
                elif sock is tcp:
                    conn, addr = tcp.accept()
                    with conn:
                        data = recv_tcp(conn)
                        if data:
                            out = handle(DNSPacket.from_bytes(data), socket.inet_aton(addr[0]), TCP)
                            if out: conn.sendall(struct.pack("!H", len(out)) + out)

            if not readable: 
                ip_counts.clear()
                if time_until_fetch > time.monotonic():
                    retried = False
                    try: 
                        fetch_records()
                        time_until_fetch = data_age + soa_refresh
                    except Exception:
                        retried = True
                        time_until_fetch += soa_retry
        except Exception as e: traceback.print_exception(e)
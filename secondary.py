from protocol.frame import *
import socket
import argparse
import hmac, hashlib
import random
from lib.libcounter import Counter
import time
from server_base import UDP, TCP, DNSSocket

BUFFER_SIZE = 1232
EDNS_SECRET = random.randbytes(8)

parser = argparse.ArgumentParser()
parser.add_argument("primary", type=str)
parser.add_argument("primary_port", type=int, default=53)
parser.add_argument("host", type=str, default="0.0.0.0")
parser.add_argument("port", type=int, default=53)
parser.add_argument("rps", type=int, default=75)
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
REQUESTS_PER_SECOND = args.rps

soa = None
soa_zone = ""
soa_serial = 0
soa_refresh = 0
soa_retry = 0
soa_expire = 0
data_age = 0
records: dict[str, list[DNSAnswer]] = {}
raw_records: list[DNSAnswer] = []

def fetch_records():
    def generate_packet(): return DNSPacket(DNSHeader(random.randint(0, 0xffff), DNSHeader_Flags(False, DNSOPCode.QUERY, False, False, False, False, False, False, DNSRCode.NOERROR)))
    global soa, soa_serial, soa_refresh, soa_retry, soa_expire, data_age, records, soa_zone, raw_records
    if soa_serial != 0 and soa_zone:
        soa_packet = generate_packet()
        soa_packet.add_question(DNSQuestion(soa_zone, DNSType.SOA, DNSClass.IN))
        soa_res = query_dns(soa_packet)
        for aw in soa_res.answers:
            if aw.type != DNSType.SOA: continue
            tokens = aw.rdata_decoded.split()
            params = {k: int(v) for k, v in (t.split("=") for t in tokens[2:])}
            if soa_serial == int(params["serial"]): return # We have the same serial
    
    packet = generate_packet()
    packet.add_question(DNSQuestion(".", DNSType.AXFR, DNSClass.IN))
    res = query_dns(packet, force_tcp=True)
    if res.header.flags.rcode != DNSRCode.NOERROR: raise Exception
    data_age = time.monotonic()
    raw_records = res.answers
    records.clear()
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

def handle(packet: DNSPacket, client_ip: bytes, transport: IntEnum):
    global soa, data_age, soa_expire
    out = DNSPacket(DNSHeader(
        packet.header.transaction_id,
        DNSHeader_Flags(True, DNSOPCode.QUERY, True, False, True, False, False, False, DNSRCode.NOERROR)
    ))

    if time.monotonic() >= (data_age + soa_expire):
        out.header.flags.rcode = DNSRCode.SERVFAIL
        out.questions = packet.questions
        out.header.num_questions = packet.header.num_questions
        return bytes(out)

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
    
    found_name = False
    for question in packet.questions:
        out.add_question(question)
        if question.qtype == DNSType.SOA and soa:
            out.add_answer(soa)
            continue
        elif question.qtype == DNSType.AXFR and raw_records:
            found_name = True
            out.answers = raw_records
            out.header.num_answers = len(raw_records)
            continue
        for record in records.get(question.qname, []):
            found_name = True
            if record.record_class != DNSClass.ANY and question.qclass != DNSClass.ANY and question.qclass != record.record_class: continue

            if record.type == question.qtype or (record.type != question.qtype and question.qtype in (DNSType.A, DNSType.AAAA) and record.type == DNSType.CNAME):
                out.add_answer(record)
                out.header.flags.rcode = DNSRCode.NOERROR
    if found_name: out.header.flags.rcode = DNSRCode.NOERROR
    else:
        out.header.flags.rcode = DNSRCode.NXDOMAIN
        if soa: out.add_authoritive_rr(soa)
   
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

    if transport == UDP and len(out) > max_size:
        out.header.flags.tc = True
        return bytes(out)[:max_size]
    return bytes(out)

class SecondaryServer(DNSSocket):
    def handle(self, *args, **kwargs): return handle(*args, **kwargs)
    def _pre_run(self):
        global data_age, soa_refresh
        fetch_records()
        self.time_until_fetch = data_age + soa_refresh
    def _idle(self):
        global data_age, soa_refresh, soa_retry
        ip_counts.clear()
        if time.monotonic() >= self.time_until_fetch:
            try: 
                fetch_records()
                self.time_until_fetch = data_age + soa_refresh
            except Exception:
                self.time_until_fetch = time.monotonic() + soa_retry
SecondaryServer(HOST, PORT, PORT, BUFFER_SIZE).run()
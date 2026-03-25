from protocol.frame import *
import socket
import argparse
import hmac, hashlib
import random
from lib.libcounter import Counter
import time
from server_base import UDP, TCP, DNSSocket, is_subdomain
from dataclasses import dataclass

BUFFER_SIZE = 1232
EDNS_SECRET = random.randbytes(8)

parser = argparse.ArgumentParser()
parser.add_argument("-p", "--primary", type=str)
parser.add_argument("-P", "--primaryport", type=int, default=53)
parser.add_argument("-H", "--host", type=str, default="0.0.0.0")
parser.add_argument("-t", "--port", type=int, default=53)
parser.add_argument("-r", "--rps", type=int, default=75)
parser.add_argument("--zone", action="append")
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

@dataclass
class SOAData:
    record: DNSAnswer
    zone: str
    serial: int
    refresh: int
    retry: int
    expire: int
    age: int
    extra_time: int = 0

soas: dict[str, SOAData] = {}

records: dict[str, tuple[list[DNSAnswer], dict[str, list[DNSAnswer]]]]

def fetch_record(zone):
    def generate_packet(): return DNSPacket(DNSHeader(random.randint(0, 0xffff), DNSHeader_Flags(False, DNSOPCode.QUERY, False, False, False, False, False, False, DNSRCode.NOERROR)))
    def delete_zone(zone):
        try: del records[zone]
        except: pass
    if soas.get(zone):
        soa_packet = generate_packet()
        soa_packet.add_question(DNSQuestion(zone, DNSType.SOA, DNSClass.IN))
        soa_res = query_dns(soa_packet)
        for aw in soa_res.answers:
            if aw.type != DNSType.SOA: continue
            tokens = aw.rdata_decoded.split()
            params = {k: int(v) for k, v in (t.split("=") for t in tokens[2:])}
            if soas[zone].serial == int(params["serial"]): return # We have the same serial

    packet = generate_packet()
    packet.add_question(DNSQuestion(zone, DNSType.AXFR, DNSClass.IN))
    res = query_dns(packet, force_tcp=True)
    if res.header.flags.rcode != DNSRCode.NOERROR: raise Exception
    data_age = time.monotonic()
    delete_zone(zone)

    out = {}
    for anwser in res.answers:
        match anwser.type: 
            case DNSType.SOA:
                tokens = anwser.rdata_decoded.split()
                params = {k: int(v) for k, v in (t.split("=") for t in tokens[2:])}

                soas[anwser.name] = SOAData(anwser, anwser.name, int(params["serial"]), int(params["refresh"]), int(params["retry"]), int(params["expire"]), data_age)
            case _: out.setdefault(anwser.name, []).append(anwser)
    records[zone] = (res.answers, out)

def fetch_records():
    for zone in args.zone: fetch_record(zone)

ip_counts: dict[bytes, Counter] = {}

def handle(packet: DNSPacket, client_ip: bytes, transport: IntEnum):
    out = DNSPacket(DNSHeader(
        packet.header.transaction_id, DNSHeader_Flags(True, DNSOPCode.QUERY, True, False, True, False, False, False, DNSRCode.NOERROR)
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
    
    found_name = False
    for question in packet.questions:
        this_zone = None
        best_len = -1
        for zone in records.keys():
            if is_subdomain(question.qname, zone) and len(zone) > best_len:
                this_zone = zone
                best_len = len(zone)
        if not this_zone: continue
        soa = soas[this_zone]
        raw_zone_records, zone_records = records[this_zone]

        if time.monotonic() >= (soa.age + soa.expire):
            out.header.flags.rcode = DNSRCode.SERVFAIL
            out.questions = packet.questions
            out.header.num_questions = packet.header.num_questions
            return bytes(out)

        out.add_question(question)

        if question.qtype == DNSType.SOA:
            out.add_answer(soa.record)
            continue
        elif question.qtype == DNSType.AXFR and client_ip == socket.inet_aton("127.0.0.1"):
            found_name = True
            out.answers = raw_zone_records
            out.header.num_answers = len(out.answers)
            continue
    
        for record in zone_records.get(question.qname, []):
            found_name = True
            if record.record_class != DNSClass.ANY and question.qclass != DNSClass.ANY and question.qclass != record.record_class: continue

            if record.type == question.qtype or (record.type != question.qtype and question.qtype in (DNSType.A, DNSType.AAAA) and record.type == DNSType.CNAME):
                out.add_answer(record)
                out.header.flags.rcode = DNSRCode.NOERROR
    if found_name: out.header.flags.rcode = DNSRCode.NOERROR
    else:
        out.header.flags.rcode = DNSRCode.NXDOMAIN
        out.add_authoritive_rr(soa.record)
   
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
        fetch_records()
    def _idle(self):
        ip_counts.clear()
        for soa in soas.values():
            if time.monotonic() >= soa.age + soa.refresh + soa.extra_time:
                try: fetch_record(soa.zone)
                except Exception: soa.extra_time += soa.retry
SecondaryServer(HOST, PORT, PORT, BUFFER_SIZE).run()
from frame import *
import socket
import traceback
import pathlib
import configparser, argparse
import hmac, hashlib
import random
import select
from libcounter import Counter


BUFFER_SIZE = 1232
EDNS_SECRET = random.randbytes(8)

parser = argparse.ArgumentParser()
parser.add_argument("config", type=str, default="config.ini")
args = parser.parse_args()

config = configparser.ConfigParser()
config.read(args.config)

RECORDS_FILE = pathlib.Path(config["records"]["file"]).resolve().absolute()
ZONE = config["soa"]["zone"].rstrip(".") + "."

HOST = config.get("server", "host", fallback="0.0.0.0")
PORT = config.getint("server", "port", fallback=53)
TCP_PORT = config.getint("server", "tcp_port", fallback=PORT)
REQUESTS_PER_SECOND = config.getint("server", "rps", fallback=75)

records_cache = None
records_mtime = None

def load_records():
    global records_cache, records_mtime

    mtime = RECORDS_FILE.stat().st_mtime
    if records_mtime == mtime: return

    records = {}  # (qname, qtype) -> (ttl, [values])

    with open(RECORDS_FILE) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith(";"): continue
            parts = line.split("\t", 3)
            if len(parts) != 4:
                print(f"[warn] skipping malformed record line: {line!r}")
                continue
            rtype, name, ttl, value = parts

            if name == "@": name = ZONE
            elif not name.endswith("."): name = name + "." + ZONE

            try: qtype = DNSType[rtype.upper()]
            except (KeyError, ValueError) as e:
                print(f"[warn] skipping record ({e}): {line!r}")
                continue

            key = (name, qtype)
            if key not in records: records[key] = (int(ttl), [])
            records[key][1].append(value)

    records_cache = records
    records_mtime = mtime
    print(f"[info] loaded {len(records)} record sets from {RECORDS_FILE}")

def get_records():
    if records_cache: return records_cache
    load_records()
    return records_cache

def resolve_records(qname: str, qtype: DNSType, client_ip: bytes):
    """
    Look up (qname, qtype) in the flat records table.
    Falls back to a wildcard entry keyed as (*.<parent>, qtype).
    Returns (ttl, values), name_exists.
    """
    records = get_records()
    qname = qname.rstrip(".") + "."  # normalise

    result = records.get((qname, qtype))
    if result:
        if result[1][0] == "!": return (1, [socket.inet_ntoa(client_ip)]), True
        return result, True

    # wildcard fallback
    labels = qname.rstrip(".").split(".")
    if len(labels) > 1:
        wildcard = "*." + ".".join(labels[1:]) + "."
        result = records.get((wildcard, qtype))
        if result: return result, True

    name_exists = any(k[0] == qname for k in records)
    return None, name_exists

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

    if packet.header.flags.qr: return
    if packet.header.flags.opcode != DNSOPCode.QUERY:
        print("Unhandled opcode:", packet.header.flags.opcode)
        return

    zone = config["soa"]["zone"]
    primary_ns = config["soa"]["primary_ns"]
    ns_ttl = config.getint("soa", "ttl", fallback=300)

    ns_list = config["soa"].get("ns", "").split(",")
    ns_list = [primary_ns] + ns_list

    def soa():
        email = config["soa"]["email"].replace("@", ".")
        refresh = config.getint("soa", "refresh", fallback=3600)
        retry = config.getint("soa", "retry", fallback=1800)
        expire = config.getint("soa", "expire", fallback=1209600)
        minimum = config.getint("soa", "min", fallback=86400)
        serial = config.get("soa", "serial", fallback="0")
        out.add_answer(DNSAnswer(
            zone, DNSType.SOA, DNSClass.IN, ns_ttl,
            rdata_decoded=(
                f"{primary_ns}. {email}. serial={serial} "
                f"refresh={refresh} retry={retry} "
                f"expire={expire} min={minimum}"
            )
        ))

    for question in packet.questions:
        out.add_question(question)
        # print(question)

        match question.qtype:
            case DNSType.SOA:
                soa()
            case DNSType.NS:
                if question.qname == zone:
                    for ns in ns_list: out.add_answer(DNSAnswer(zone, DNSType.NS, DNSClass.IN, ns_ttl, rdata_decoded=ns))
            case DNSType.AXFR:
                if transport != TCP or client_ip != socket.inet_aton("127.0.0.1"):
                    out.header.flags.rcode = DNSRCode.REFUSED
                    break

                records = get_records()
                if not records: continue

                soa()
                for (name, qtype), (ttl, values) in records.items():
                    for value in values: out.add_answer(DNSAnswer(name, qtype, DNSClass.IN, ttl, rdata_decoded=value))
                for ns in ns_list: out.add_answer(DNSAnswer(zone, DNSType.NS, DNSClass.IN, ns_ttl, rdata_decoded=ns))

                soa()
            case _:
                result, exists = resolve_records(question.qname, question.qtype, client_ip)

                qtype_out = question.qtype
                if not result and question.qtype != DNSType.CNAME and question.qtype in (DNSType.A, DNSType.AAAA):
                    cname_result, cname_exists = resolve_records(question.qname, DNSType.CNAME, client_ip)
                    if cname_result:
                        result = cname_result
                        exists = cname_exists
                        qtype_out = DNSType.CNAME

                if result:
                    ttl, values = result
                    for value in values:
                        out.add_answer(DNSAnswer(
                            question.qname, qtype_out,
                            DNSClass.IN, ttl, rdata_decoded=value
                        ))
                elif exists: out.header.flags.rcode = DNSRCode.NOERROR
                else:
                    out.header.flags.rcode = DNSRCode.NXDOMAIN
                    soa()
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
    out.add_additional_rr(EDNSOptRecord(config.getboolean("records", "dnssec", fallback=False), max_size, edns_options))
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
udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
udp.bind((HOST, PORT))

tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcp.bind((HOST, TCP_PORT))
tcp.listen(32)

print(f"UDP listening on {HOST}:{PORT}")
print(f"TCP listening on {HOST}:{TCP_PORT}")

with udp, tcp:
    load_records() # Preload

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
                load_records()
                ip_counts = {}
        except Exception as e: traceback.print_exception(e)
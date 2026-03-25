from protocol.frame import *
import socket
import pathlib, datetime
import configparser, argparse
import hmac, hashlib, random
from lib.libcounter import Counter
from server_base import DNSSocket, UDP, TCP

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

soa_serial = config.getint("soa", "serial", fallback=0)
def compute_soa_serial(d):
    t = datetime.datetime.now()
    return (t.year * 1_000_000) + (t.month * 10_000) + (t.day * 100) + d

records_cache = None
records_mtime = None

def load_records():
    global records_cache, records_mtime, soa_serial

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
            if records[key][0] < int(ttl): 
                print(f"[warn] mismatching ttl values on {name}, setting all to highest ttl (server does not support multiple ttls as of now)")
                records[key] = (int(ttl), records[key][1])
            records[key][1].append(value)

    records_cache = records
    records_mtime = mtime
    soa_serial += 1
    print(f"[info] loaded {len(records)} record sets from {RECORDS_FILE}")

def get_records():
    if records_cache: return records_cache
    load_records()
    return records_cache

def resolve_records(qname: str, qtype: DNSType, client_ip: bytes):
    records = get_records()
    if not records: raise Exception
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
    else: ip_counts[client_ip] = Counter().beat()

    if packet.header.flags.qr: return
    if packet.header.flags.opcode != DNSOPCode.QUERY:
        print("Unhandled opcode:", packet.header.flags.opcode)
        return

    zone = config["soa"]["zone"]
    primary_ns = config["soa"]["primary_ns"]
    ns_ttl = config.getint("soa", "ttl", fallback=300)

    ns_list = config["soa"].get("ns", "").split(",")
    ns_list = [primary_ns] + ns_list

    def soa(add_func = out.add_answer):
        email = config["soa"]["email"].replace("@", ".")
        refresh = config.getint("soa", "refresh", fallback=3600)
        retry = config.getint("soa", "retry", fallback=1800)
        expire = config.getint("soa", "expire", fallback=1209600)
        minimum = config.getint("soa", "min", fallback=3600)
        add_func(DNSAnswer(
            zone, DNSType.SOA, DNSClass.IN, ns_ttl,
            rdata_decoded=(
                f"{primary_ns}. {email}. serial={compute_soa_serial(soa_serial)} "
                f"refresh={refresh} retry={retry} "
                f"expire={expire} min={minimum}"
            )
        ))

    for question in packet.questions:
        out.add_question(question)
        # print(question)

        match question.qtype:
            case DNSType.SOA: soa()
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
                    soa(out.add_authoritive_rr)
   
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

    if transport == UDP and len(out) > max_size:
        out.header.flags.tc = True
        return bytes(out)[:max_size]
    return bytes(out)

class PrimaryServer(DNSSocket):
    def _pre_run(self): load_records()
    def handle(self, *args, **kwargs): return handle(*args, **kwargs)
    def _idle(self):
        load_records()
        ip_counts.clear()
PrimaryServer(HOST, PORT, TCP_PORT, BUFFER_SIZE).run()
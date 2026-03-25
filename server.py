from protocol.frame import *
import socket
import pathlib, datetime
import configparser, argparse
import hmac, hashlib, random
from dataclasses import dataclass, field
from lib.libcounter import Counter
from server_base import DNSSocket, UDP, TCP, is_subdomain  # reuse is_subdomain from secondary

BUFFER_SIZE = 1232
EDNS_SECRET = random.randbytes(8)

parser = argparse.ArgumentParser()
parser.add_argument("config", type=str, default="config.ini")
args = parser.parse_args()

config = configparser.ConfigParser()
config.read(args.config)

HOST = config.get("server", "host", fallback="0.0.0.0")
PORT = config.getint("server", "port", fallback=53)
TCP_PORT = config.getint("server", "tcp_port", fallback=PORT)
REQUESTS_PER_SECOND = config.getint("server", "rps", fallback=75)

@dataclass
class Zone:
    name: str
    records_file: pathlib.Path
    primary_ns: str
    ns_list: list[str]
    soa_cfg: dict
    serial: int = 0
    records_cache: dict = field(default_factory=dict)
    records_mtime: float | None = None

    def axfr_allowed(self, client_ip: bytes) -> bool:
        if socket.inet_aton("127.0.0.1") == client_ip: return True
        for ns in self.ns_list:
            try:
                if socket.inet_aton(socket.gethostbyname(ns)) == client_ip: return True
            except OSError: pass
        return False

    def compute_soa_serial(self):
        t = datetime.datetime.now()
        return (t.year * 1_000_000) + (t.month * 10_000) + (t.day * 100) + self.serial

    def load(self):
        mtime = self.records_file.stat().st_mtime
        if self.records_mtime == mtime: return

        records = {}
        with open(self.records_file) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith(";"):
                    continue
                parts = line.split("\t", 3)
                if len(parts) != 4:
                    print(f"[warn] skipping malformed line: {line!r}")
                    continue
                rtype, name, ttl, value = parts

                if name == "@": name = self.name
                elif not name.endswith("."): name = name + "." + self.name

                try: qtype = DNSType[rtype.upper()]
                except (KeyError, ValueError) as e:
                    print(f"[warn] skipping record ({e}): {line!r}")
                    continue

                key = (name, qtype)
                if key not in records: records[key] = (int(ttl), [])
                if records[key][0] < int(ttl):
                    print(f"[warn] mismatched TTL on {name}, using highest")
                    records[key] = (int(ttl), records[key][1])
                records[key][1].append(value)

        self.records_cache = records
        self.records_mtime = mtime
        self.serial += 1
        print(f"[info] [{self.name}] loaded {len(records)} record sets")

    def resolve(self, qname: str, qtype: DNSType, client_ip: bytes):
        qname = qname.rstrip(".") + "."
        result = self.records_cache.get((qname, qtype))
        if result:
            if result[1][0] == "!": return (1, [socket.inet_ntoa(client_ip)]), True
            return result, True

        labels = qname.rstrip(".").split(".")
        if len(labels) > 1:
            wildcard = "*." + ".".join(labels[1:]) + "."
            result = self.records_cache.get((wildcard, qtype))
            if result: return result, True

        name_exists = any(k[0] == qname for k in self.records_cache)
        return None, name_exists

zones: list[Zone] = []

for section in config.sections():
    if not section.startswith("zone:"):
        continue
    zone_name = section[len("zone:"):].rstrip(".") + "."
    sec = config[section]
    primary_ns = sec["primary_ns"]
    ns_list = [primary_ns] + [n for n in sec.get("ns", "").split(",") if n]
    zones.append(Zone(
        name=zone_name,
        records_file=pathlib.Path(sec["file"]).resolve(),
        primary_ns=primary_ns,
        ns_list=ns_list,
        soa_cfg={
            "email": sec.get("email", "hostmaster." + zone_name),
            "ttl": sec.getint("ttl", 300),
            "refresh": sec.getint("refresh", 3600),
            "retry": sec.getint("retry", 1800),
            "expire": sec.getint("expire", 1209600),
            "min": sec.getint("min", 3600),
        },
        serial=sec.getint("serial", 0),
    ))

if not zones: raise RuntimeError("No [zone:*] sections found in config")

def find_zone(qname: str) -> Zone | None:
    """Return the most specific (longest) zone that is an ancestor of qname."""
    best: Zone | None = None
    best_len = -1
    for z in zones:
        if is_subdomain(qname, z.name) and len(z.name) > best_len:
            best = z
            best_len = len(z.name)
    return best

def load_all():
    for z in zones:
        try: z.load()
        except Exception as e:
            print(f"[error] loading zone {z.name}: {e}")

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

    for question in packet.questions:
        out.add_question(question)

        zone = find_zone(question.qname)
        if zone is None or not zone.records_cache:
            out.header.flags.rcode = DNSRCode.REFUSED
            continue

        ns_ttl = zone.soa_cfg["ttl"]

        def soa(add_func=out.add_answer, z=zone):
            email = z.soa_cfg["email"].replace("@", ".")
            add_func(DNSAnswer(
                z.name, DNSType.SOA, DNSClass.IN, z.soa_cfg["ttl"],
                rdata_decoded=(
                    f"{z.primary_ns}. {email}. serial={z.compute_soa_serial()} "
                    f"refresh={z.soa_cfg['refresh']} retry={z.soa_cfg['retry']} "
                    f"expire={z.soa_cfg['expire']} min={z.soa_cfg['min']}"
                )
            ))

        match question.qtype:
            case DNSType.SOA: soa()
            case DNSType.NS:
                if question.qname.rstrip(".") + "." == zone.name:
                    for ns in zone.ns_list: out.add_answer(DNSAnswer(zone.name, DNSType.NS, DNSClass.IN, ns_ttl, rdata_decoded=ns))
            case DNSType.AXFR:
                if transport == TCP and zone.axfr_allowed(client_ip):
                    soa()
                    for (name, qtype), (ttl, values) in zone.records_cache.items():
                        for value in values:
                            out.add_answer(DNSAnswer(name, qtype, DNSClass.IN, ttl, rdata_decoded=value))
                    for ns in zone.ns_list:
                        out.add_answer(DNSAnswer(zone.name, DNSType.NS, DNSClass.IN, ns_ttl, rdata_decoded=ns))
                    soa()
            case _:
                result, exists = zone.resolve(question.qname, question.qtype, client_ip)

                qtype_out = question.qtype
                if not result and question.qtype != DNSType.CNAME and question.qtype in (DNSType.A, DNSType.AAAA):
                    cname_result, cname_exists = zone.resolve(question.qname, DNSType.CNAME, client_ip)
                    if cname_result: result, exists, qtype_out = cname_result, cname_exists, DNSType.CNAME

                if result:
                    ttl, values = result
                    for value in values: out.add_answer(DNSAnswer(question.qname, qtype_out, DNSClass.IN, ttl, rdata_decoded=value))
                elif exists: out.header.flags.rcode = DNSRCode.NOERROR
                else:
                    out.header.flags.rcode = DNSRCode.NXDOMAIN
                    soa(out.add_authoritive_rr)

    max_size = BUFFER_SIZE
    edns_options = []
    for additional in packet.additional:
        if isinstance(additional, EDNSOptRecord):
            if max_size > additional.max_udp_size:
                max_size = additional.max_udp_size
            for option in additional.options:
                if option.code == EDNSOptionCode.COOKIE:
                    edns_options.append(EDNSOption(
                        EDNSOptionCode.COOKIE,
                        option.data + hmac.new(EDNS_SECRET, option.data + client_ip, hashlib.md5).digest()
                    ))
    out.add_additional_rr(EDNSOptRecord(False, max_size, edns_options))

    if transport == UDP and len(out) > max_size:
        out.header.flags.tc = True
        return bytes(out)[:max_size]
    return bytes(out)

class PrimaryServer(DNSSocket):
    def _pre_run(self): load_all()
    def handle(self, *args, **kwargs): return handle(*args, **kwargs)
    def _idle(self):
        load_all()
        ip_counts.clear()
PrimaryServer(HOST, PORT, TCP_PORT, BUFFER_SIZE).run()
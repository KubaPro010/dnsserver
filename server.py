from protocol.frame import *
import socket
import pathlib, datetime
import configparser, argparse
import hmac, hashlib, random
from dataclasses import dataclass, field
from lib.libcounter import Counter
from server_base import DNSSocket, UDP, TCP, is_subdomain, _parse_soa_serial, query_dns
import threading

BUFFER_SIZE = 1232
EDNS_SECRET = random.randbytes(8)
MAX_JOURNAL_ENTRIES = 100

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
class JournalEntry:
    old_soa_serial: int
    new_soa_serial: int
    additions: list[DNSAnswer]
    deletions: list[DNSAnswer]

soa_journal: dict[str, list[JournalEntry]] = {}

def get_journal_chain(zone_name: str, from_serial: int, to_serial: int) -> list[JournalEntry] | None:
    if from_serial == to_serial: return []

    entries = soa_journal.get(zone_name, [])
    entry_map: dict[int, JournalEntry] = {e.old_soa_serial: e for e in entries}

    chain: list[JournalEntry] = []
    current = from_serial
    while current != to_serial:
        entry = entry_map.get(current)
        if entry is None: return None
        chain.append(entry)
        current = entry.new_soa_serial
    return chain


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

    def notify_all_ns(self):
        def generate_packet(): return DNSPacket(DNSHeader(random.randint(0, 0xffff), DNSHeader_Flags(False, DNSOPCode.NOTIFY, True, False, False, False, False, False, DNSRCode.NOERROR)))
        primary_ns = self.primary_ns
        soa_cfg = self.soa_cfg
        serial = self.serial
        name = self.name
        for ns in self.ns_list[:]:
            if ns == primary_ns: continue

            packet = generate_packet().add_question(DNSQuestion(name, DNSType.SOA, DNSClass.IN))
            email = soa_cfg["email"].replace("@", ".")
            packet.add_answer(DNSAnswer(
                name, DNSType.SOA, DNSClass.IN, soa_cfg["ttl"],
                rdata_decoded=(
                    f"{primary_ns}. {email}. serial={self.compute_soa_serial(serial)} "
                    f"refresh={soa_cfg['refresh']} retry={soa_cfg['retry']} "
                    f"expire={soa_cfg['expire']} min={soa_cfg['min']}"
                )
            ))
            try: query_dns(packet, ns, BUFFER_SIZE)
            except Exception as e: print(f"Could not notify {ns} ({e})")

    def compute_soa_serial(self, serial: int | None = None):
        if serial is None: serial = self.serial
        t = datetime.datetime.now()
        return (t.year * 1_000_000) + (t.month * 10_000) + (t.day * 100) + serial

    def _diff_records(self, old_cache: dict, new_cache: dict) -> tuple[list, list]:
        deletions: list = []
        additions: list = []

        for (name, qtype), (ttl, values) in old_cache.items():
            new_entry = new_cache.get((name, qtype))
            if new_entry is None: old_set = set(values)
            else:
                _, new_values = new_entry
                old_set = set(values) - set(new_values)
            for v in old_set:
                deletions.append(DNSAnswer(name, qtype, DNSClass.IN, ttl, rdata_decoded=v))

        for (name, qtype), (ttl, values) in new_cache.items():
            old_entry = old_cache.get((name, qtype))
            if old_entry is None: new_set = set(values)
            else:
                _, old_values = old_entry
                new_set = set(values) - set(old_values)
            for v in new_set:
                additions.append(DNSAnswer(name, qtype, DNSClass.IN, ttl, rdata_decoded=v))

        return additions, deletions

    def load(self):
        mtime = self.records_file.stat().st_mtime
        if self.records_mtime == mtime: return

        new_records = {}
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
                if key not in new_records: new_records[key] = (int(ttl), [])
                if new_records[key][0] < int(ttl):
                    print(f"[warn] mismatched TTL on {name}, using highest")
                    new_records[key] = (int(ttl), new_records[key][1])
                new_records[key][1].append(value)

        old_cache = self.records_cache
        if old_cache:
            old_soa_serial = self.compute_soa_serial()
            additions, deletions = self._diff_records(old_cache, new_records)

            self.serial += 1
            new_soa_serial = self.compute_soa_serial()

            entry = JournalEntry(
                old_soa_serial=old_soa_serial,
                new_soa_serial=new_soa_serial,
                additions=additions,
                deletions=deletions,
            )
            journal = soa_journal.setdefault(self.name, [])
            journal.append(entry)
            # Cap journal size to avoid unbounded memory growth.
            if len(journal) > MAX_JOURNAL_ENTRIES: del journal[: len(journal) - MAX_JOURNAL_ENTRIES]
        else: self.serial += 1

        self.records_cache = new_records
        self.records_mtime = mtime

        threading.Thread(target=self.notify_all_ns).run()

        print(f"[info] [{self.name}] loaded {len(new_records)} record sets "
              f"(serial={self.compute_soa_serial()})")

    def resolve(self, qname: str, qtype: DNSType):
        qname = qname.rstrip(".") + "."
        result = self.records_cache.get((qname, qtype))
        if result: return result, True
        name_exists = any(k[0] == qname for k in self.records_cache)
        if name_exists: return None, True

        labels = qname.rstrip(".").split(".")
        if len(labels) > 1:
            wildcard = "*." + ".".join(labels[1:]) + "."
            result = self.records_cache.get((wildcard, qtype))
            if result: return result, True

        return None, False

zones: list[Zone] = []

for section in config.sections():
    if not section.startswith("zone:"): continue
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

    if packet.header.flags.qr:
        out.header.flags.rcode = DNSRCode.REFUSED
        return bytes(out)
    if packet.header.flags.opcode != DNSOPCode.QUERY:
        print("Unhandled opcode:", packet.header.flags.opcode)
        out.header.flags.rcode = DNSRCode.NOTIMP
        return bytes(out)

    for question in packet.questions:
        out.add_question(question)

        zone = find_zone(question.qname)
        if zone is None or not zone.records_cache:
            out.header.flags.rcode = DNSRCode.REFUSED
            continue
        qask = question.qname.rstrip(".") + "."

        ns_ttl = zone.soa_cfg["ttl"]

        def soa(add_func=out.add_answer, z=zone, serial_override=None):
            email = z.soa_cfg["email"].replace("@", ".")
            s = serial_override if serial_override is not None else z.compute_soa_serial()
            add_func(DNSAnswer(
                z.name, DNSType.SOA, DNSClass.IN, z.soa_cfg["ttl"],
                rdata_decoded=(
                    f"{z.primary_ns}. {email}. serial={s} "
                    f"refresh={z.soa_cfg['refresh']} retry={z.soa_cfg['retry']} "
                    f"expire={z.soa_cfg['expire']} min={z.soa_cfg['min']}"
                )
            ))
        def afxr(z=zone):
            if transport == TCP and z.axfr_allowed(client_ip):
                soa()
                for (name, qtype), (ttl, values) in z.records_cache.items():
                    for value in values:
                        out.add_answer(DNSAnswer(name, qtype, DNSClass.IN, ttl, rdata_decoded=value))
                for ns in z.ns_list:
                    out.add_answer(DNSAnswer(z.name, DNSType.NS, DNSClass.IN, ns_ttl, rdata_decoded=ns))
                soa()
            else: out.header.flags.rcode = DNSRCode.REFUSED

        match question.qtype:
            case DNSType.SOA: soa()
            case DNSType.NS:
                if qask == zone.name:
                    for ns in zone.ns_list: out.add_answer(DNSAnswer(zone.name, DNSType.NS, DNSClass.IN, ns_ttl, rdata_decoded=ns))
            case DNSType.AXFR: afxr()
            case DNSType.IXFR:
                if transport != TCP or not zone.axfr_allowed(client_ip):
                    out.header.flags.rcode = DNSRCode.REFUSED
                    continue

                client_serial: int | None = None
                for auth_rr in packet.authority:
                    if auth_rr.type == DNSType.SOA:
                        client_serial = _parse_soa_serial(auth_rr.rdata_decoded)
                        break

                current_serial = zone.compute_soa_serial()

                if client_serial is None:
                    print(f"[ixfr] [{zone.name}] no client serial, falling back to AXFR")
                    afxr()
                    continue

                if client_serial == current_serial:
                    soa()
                    continue

                chain = get_journal_chain(zone.name, client_serial, current_serial)

                if chain is None:
                    # Journal doesn't cover the requested range — full AXFR fallback.
                    print(f"[ixfr] [{zone.name}] journal gap from {client_serial} to {current_serial}, falling back to AXFR")
                    afxr()
                    continue
                soa()  # opening new SOA
                for entry in chain:
                    soa(serial_override=entry.old_soa_serial)   # start of deletion set
                    for rr in entry.deletions: out.add_answer(rr)
                    soa(serial_override=entry.new_soa_serial)   # start of addition set
                    for rr in entry.additions: out.add_answer(rr)
                soa()

                print(f"[ixfr] [{zone.name}] sent {len(chain)} delta(s) "
                      f"from serial {client_serial} to {current_serial}")
            case _:
                result, exists = zone.resolve(question.qname, question.qtype)

                qtype_out = question.qtype
                if not result and question.qtype != DNSType.CNAME and question.qtype in (DNSType.A, DNSType.AAAA):
                    cname_result, cname_exists = zone.resolve(question.qname, DNSType.CNAME)
                    if cname_result: result, exists, qtype_out = cname_result, cname_exists, DNSType.CNAME

                if result:
                    ttl, values = result
                    for value in values: out.add_answer(DNSAnswer(question.qname, qtype_out, DNSClass.IN, ttl, rdata_decoded=value))
                elif exists: 
                    out.header.flags.rcode = DNSRCode.NOERROR
                    soa(out.add_authoritive_rr)
                else:
                    if qask != zone.name: out.header.flags.rcode = DNSRCode.NXDOMAIN
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
                        option.data + hmac.digest(EDNS_SECRET, option.data + client_ip, hashlib.md5)
                    ))
    out.add_additional_rr(EDNSOptRecord(False, max_size, edns_options))

    bout = bytes(out)
    if transport == UDP and len(bout) > max_size:
        out.header.flags.tc = True
        return bytes(out)[:max_size]
    return bout

class PrimaryServer(DNSSocket):
    def _pre_run(self): load_all()
    def handle(self, *args, **kwargs): return handle(*args, **kwargs)
    def _idle(self):
        load_all()
        for ip, counter in ip_counts.items():
            if counter.get_rate() < (REQUESTS_PER_SECOND / 2): del ip_counts[ip]
PrimaryServer(HOST, PORT, TCP_PORT, BUFFER_SIZE).run()
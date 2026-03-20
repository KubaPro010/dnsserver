from frame import *
import socket
import traceback
import pathlib
import configparser, argparse
import hmac, hashlib

BUFFER_SIZE = 4096
EDNS_SECRET = b"flerken"

parser = argparse.ArgumentParser()
parser.add_argument("config", type=str, default="config.ini")
args = parser.parse_args()

config = configparser.ConfigParser()
config.read(args.config)

RECORDS_FILE = pathlib.Path(config["records"]["file"]).resolve()
ZONE = config["soa"]["zone"].rstrip(".") + "."

HOST = "0.0.0.0"
PORT = 53

records_cache = None
records_mtime = None

def load_records():
    """
    Load records from a tab-separated file.
    Format (one record per line):
        type  name  ttl  value
    Name rules:
        @        → zone apex
        www      → relative, zone appended  (www.example.com.)
        foo.org. → trailing dot = FQDN, used as-is
    Lines starting with # are ignored.
    """
    global records_cache, records_mtime

    mtime = RECORDS_FILE.stat().st_mtime
    if records_mtime == mtime:
        return records_cache

    records = {}  # (qname, qtype) -> (ttl, [values])

    with open(RECORDS_FILE) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t", 3)
            if len(parts) != 4:
                print(f"[warn] skipping malformed record line: {line!r}")
                continue
            rtype, name, ttl, value = parts

            if name == "@":
                name = ZONE
            elif not name.endswith("."):
                name = name + "." + ZONE
            # else already a FQDN

            try:
                qtype = DNSType[rtype.upper()]
                ttl = int(ttl)
            except (KeyError, ValueError) as e:
                print(f"[warn] skipping record ({e}): {line!r}")
                continue

            key = (name, qtype)
            if key not in records:
                records[key] = (ttl, [])
            records[key][1].append(value)

    records_cache = records
    records_mtime = mtime
    print(f"[info] loaded {len(records)} record sets from {RECORDS_FILE}")
    return records

def resolve_records(qname: str, qtype: DNSType, client_ip: bytes):
    """
    Look up (qname, qtype) in the flat records table.
    Falls back to a wildcard entry keyed as (*.<parent>, qtype).
    Returns (ttl, values), name_exists.
    """
    records = load_records()
    qname = qname.rstrip(".") + "."  # normalise

    result = records.get((qname, qtype))
    if result:
        print(result)
        if result[1][0] == "!":
            return (1, [socket.inet_ntoa(client_ip)]), True
        return result, True

    # wildcard fallback
    labels = qname.rstrip(".").split(".")
    if len(labels) > 1:
        wildcard = "*." + ".".join(labels[1:]) + "."
        result = records.get((wildcard, qtype))
        if result:
            return result, True

    name_exists = any(k[0] == qname for k in records)
    return None, name_exists


def handle(packet: DNSPacket, client_ip: bytes):
    out = DNSPacket(DNSHeader(
        packet.header.transaction_id,
        DNSHeader_Flags(True, DNSOPCode.QUERY, True, False, False, False, False, False, DNSRCode.NOERROR)
    ))
    if packet.header.flags.qr: return
    if packet.header.flags.opcode != DNSOPCode.QUERY:
        print("Unhandled opcode:", packet.header.flags.opcode)
        return

    zone = config["soa"]["zone"]
    primary_ns = config["soa"]["primary_ns"]

    def soa():
        if config.has_section("soa"):
            email = config["soa"]["email"].replace("@", ".")
            refresh = config.getint("soa", "refresh", fallback=3600)
            retry = config.getint("soa", "retry", fallback=1800)
            expire = config.getint("soa", "expire", fallback=1209600)
            minimum = config.getint("soa", "min", fallback=86400)
            serial = config.get("soa", "serial", fallback="0")
            ttl = config.getint("soa", "ttl", fallback=300)
            out.add_answer(DNSAnswer(
                zone, DNSType.SOA, DNSClass.IN, ttl,
                rdata_decoded=(
                    f"{primary_ns}. {email}. serial={serial} "
                    f"refresh={refresh} retry={retry} "
                    f"expire={expire} min={minimum}"
                )
            ))

    for question in packet.questions:
        out.add_question(question)
        print(question)

        match question.qtype:
            case DNSType.SOA:
                soa()
            case _:
                if question.qtype == DNSType.NS and question.qname == zone:
                    out.add_answer(DNSAnswer(
                        zone, DNSType.NS, DNSClass.IN, 300,
                        rdata_decoded=primary_ns
                    ))
                    continue

                result, exists = resolve_records(question.qname, question.qtype, client_ip)

                # No direct match — check for a CNAME so the recursive
                # resolver (e.g. 1.1.1.1) can follow the chain itself.
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
    edns_options = []
    for additional in packet.additional:
        if isinstance(additional, EDNSOptRecord):
            print(additional)
            for option in additional.options:
                match option.code:
                    case EDNSOptionCode.COOKIE:
                        edns_options.append(EDNSOption(EDNSOptionCode.COOKIE, option.data + hmac.new(EDNS_SECRET, option.data + client_ip, hashlib.md5).digest()))
    out.add_additional_rr(EDNSOptRecord(config.getboolean("records", "dnssec", fallback=False), BUFFER_SIZE, edns_options))

    return bytes(out)

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.bind((HOST, PORT))
    s.settimeout(1)
    print(f"UDP server listening on {HOST}:{PORT}")

    while True:
        try:
            data, addr = s.recvfrom(BUFFER_SIZE)
            if not data: break
            out = handle(DNSPacket.from_bytes(data), socket.inet_aton(addr[0]))
            if out: s.sendto(out, addr)
        except TimeoutError: pass
        except Exception as e:
            traceback.print_exception(e)
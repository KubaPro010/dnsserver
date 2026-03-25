import struct, socket
from dataclasses import dataclass, field
from protocol.const import *
from protocol.decode import decode_rdata, decode_name

@dataclass
class EDNSOption:
    code: EDNSOptionCode
    data: bytes
    def __bytes__(self):
        return struct.pack("!HH", self.code, len(self.data)) + self.data
    @staticmethod
    def from_bytes(data: bytes, offset: int = 0) -> tuple["EDNSOption", int]:
        code, data_len = struct.unpack_from("!HH", data, offset)
        offset += 4
        payload = data[offset:offset+data_len]
        offset += data_len
        return EDNSOption(code, payload), offset

@dataclass
class EDNSOptRecord:
    dnssec: bool
    max_udp_size: int
    options: list[EDNSOption]
    flags: int = 0
    extended_rcode: int = 0
    version: int = 0
    def __bytes__(self) -> bytes:
        ttl = (
            (self.extended_rcode & 0xFF) << 24 |
            (self.version & 0xFF) << 16 |
            (self.dnssec & 0x1) << 15
        )
        record = DNSAnswer("", DNSType.OPT, self.max_udp_size, ttl)
        for option in self.options: record.rdata += bytes(option)
        return bytes(record)
    def to_bytes(self, *args, **kwargs): return bytes(self)
    @staticmethod
    def from_bytes(data: bytes, offset: int) -> tuple["EDNSOptRecord", int]:
        while data[offset] != 0: offset += data[offset] + 1
        offset += 1

        offset += 2
        max_udp_size = int.from_bytes(data[offset:offset+2], "big")
        offset += 2

        ttl = int.from_bytes(data[offset:offset+4], "big")
        offset += 4
        extended_rcode = (ttl >> 24) & 0xFF
        version = (ttl >> 16) & 0xFF
        dnssec = bool((ttl >> 15) & 0x1)
        flags = ttl & 0x7FFF  # lower 15 bits (excluding dnssec)

        rdlength = int.from_bytes(data[offset:offset+2], "big")
        offset += 2
        rdata_end = offset + rdlength

        options = []
        while offset < rdata_end:
            opt_code = int.from_bytes(data[offset:offset+2], "big")
            offset += 2
            opt_length = int.from_bytes(data[offset:offset+2], "big")
            offset += 2
            opt_data = data[offset:offset+opt_length]
            offset += opt_length
            options.append(EDNSOption(EDNSOptionCode(opt_code), opt_data))

        return EDNSOptRecord(dnssec=dnssec, max_udp_size=max_udp_size, options=options, flags=flags, extended_rcode=extended_rcode, version=version), offset

@dataclass
class DNSHeader_Flags:
    qr: bool # 1 = reply
    opcode: DNSOPCode
    aa: bool
    tc: bool
    rd: bool
    ra: bool
    ad: bool
    cd: bool
    rcode: DNSRCode

    def __int__(self):
        return (
            self.qr << 15 |
            (self.opcode & 0b1111) << 11 |
            self.aa << 10 |
            self.tc << 9 |
            self.rd << 8 |
            self.ra << 7 |
            self.ad << 5 |
            self.cd << 4 |
            self.rcode & 0b1111
        )

    def __bytes__(self): return struct.pack("!H", int(self))

    def __str__(self):
        flags = []
        if self.qr: flags.append("QR")
        if self.aa: flags.append("AA")
        if self.tc: flags.append("TC")
        if self.rd: flags.append("RD")
        if self.ra: flags.append("RA")
        if self.ad: flags.append("AD")
        if self.cd: flags.append("CD")
        return (f"{self.opcode.name} "
                f"{' '.join(flags)} "
                f"{self.rcode.name}")

    @classmethod
    def from_int(cls, value: int) -> "DNSHeader_Flags":
        return cls(
            qr = bool(value >> 15 & 1),
            opcode = DNSOPCode(value >> 11 & 0b1111),
            aa = bool(value >> 10 & 1),
            tc = bool(value >> 9 & 1),
            rd = bool(value >> 8 & 1),
            ra = bool(value >> 7 & 1),
            ad = bool(value >> 5 & 1),
            cd = bool(value >> 4 & 1),
            rcode = DNSRCode(value & 0b1111),
        )

@dataclass
class DNSHeader:
    transaction_id: int
    flags: DNSHeader_Flags
    num_questions: int = 0
    num_answers: int = 0
    num_authority_rr: int = 0
    num_additional_rr: int = 0

    def __bytes__(self):
        return struct.pack("!HHHHHH",
            self.transaction_id, int(self.flags),
            self.num_questions, self.num_answers,
            self.num_authority_rr, self.num_additional_rr)

    def __len__(self): return 12

    @classmethod
    def from_bytes(cls, data: bytes) -> "DNSHeader":
        tid, flags, nq, na, nauth, nadd = struct.unpack_from("!HHHHHH", data, 0)
        return cls(tid, DNSHeader_Flags.from_int(flags), nq, na, nauth, nadd)

@dataclass
class DNSQuestion:
    qname: str
    qtype: DNSType
    qclass: DNSClass | int

    def to_bytes(self):
        out = b""
        for part in self.qname.split("."):
            label = part.encode()
            if not label: continue
            if len(label) > 63: raise ValueError(f"DNS label too long: {label}")
            out += struct.pack("!B", len(label)) + label
        out += b"\x00"
        out += struct.pack("!HH", self.qtype, self.qclass)
        return out

    def __bytes__(self): return self.to_bytes()
    def __len__(self): return len(bytes(self))
    def __str__(self): return f"{self.qname} {self.qtype.name} {DNSClass(self.qclass).name}"

    @classmethod
    def from_bytes(cls, data: bytes, offset: int) -> tuple["DNSQuestion", int]:
        name, offset = decode_name(data, offset)
        qtype, qclass = struct.unpack_from("!HH", data, offset)
        return cls(name, DNSType(qtype), DNSClass(qclass)), offset + 4

def encode_name(name: str) -> bytes:
    if name in ("", "."): return b"\x00"
    out = b""
    for label in name.rstrip(".").split("."):
        encoded = label.encode()
        if len(encoded) > 63: raise ValueError(f"DNS label too long: {label}")
        out += struct.pack("!B", len(encoded)) + encoded
    return out + b"\x00"

def encode_rdata(rtype: DNSType, rdata_decoded: str) -> bytes:
    match rtype:
        case DNSType.A:
            return socket.inet_aton(rdata_decoded)
        case DNSType.AAAA:
            return socket.inet_pton(socket.AF_INET6, rdata_decoded)
        case DNSType.NS | DNSType.CNAME | DNSType.PTR:
            return encode_name(rdata_decoded)
        case DNSType.MX:
            pref, name = rdata_decoded.split(" ", 1)
            return struct.pack("!H", int(pref)) + encode_name(name)
        case DNSType.TXT:
            encoded = rdata_decoded.encode()
            # single string, chunked at 255 bytes
            out = b""
            for i in range(0, max(len(encoded), 1), 255):
                chunk = encoded[i:i+255]
                out += struct.pack("!B", len(chunk)) + chunk
            return out
        case DNSType.SOA:
            tokens = rdata_decoded.split()
            mname = tokens[0]
            rname = tokens[1]
            params = {k: int(v) for k, v in (t.split("=") for t in tokens[2:])}
            return (
                encode_name(mname) + encode_name(rname)
                + struct.pack("!IIIII",
                    params["serial"], params["refresh"],
                    params["retry"],  params["expire"], params["min"])
            )

    return bytes.fromhex(rdata_decoded)

@dataclass
class DNSAnswer:
    name: str
    type: DNSType
    record_class: DNSClass | int
    ttl: int
    rdata: bytes = b""
    rdata_decoded: str = field(default="", repr=False)

    def encode_name(self, offset_map: dict | None = None, current_offset: int = 0) -> bytes:
        if self.name in ("", "."): return b"\x00"
        out = b""
        parts = self.name.rstrip(".").split(".")
        for i in range(len(parts)):
            suffix = ".".join(parts[i:])
            if offset_map is not None and suffix in offset_map:
                out += struct.pack("!H", 0xC000 | offset_map[suffix])
                return out
            label = parts[i].encode()
            if len(label) > 63: raise ValueError("DNS label too long")
            if offset_map is not None and suffix not in offset_map:
                offset_map[suffix] = current_offset + len(out)
            out += struct.pack("!B", len(label)) + label
        out += b"\x00"
        return out

    def get_rdata_bytes(self) -> bytes:
        if self.rdata: return self.rdata
        if self.rdata_decoded:
            return encode_rdata(
                self.type,
                self.rdata_decoded
            )
        return b""

    def to_bytes(self, offset_map: dict | None = None, current_offset: int = 0):
        name_bytes = self.encode_name(offset_map, current_offset)
        rdata = self.get_rdata_bytes()
        rest = struct.pack(
            "!HHIH",
            self.type,
            self.record_class,
            self.ttl,
            len(rdata)
        ) + rdata
        return name_bytes + rest

    def __bytes__(self): return self.to_bytes()

    def __str__(self):
        return f"{self.name} TTL={self.ttl} {DNSType(self.type).name} {self.rdata_decoded or self.rdata.hex()}"

    @classmethod
    def from_bytes(cls, data: bytes, offset: int) -> tuple["DNSAnswer", int]:
        name, offset = decode_name(data, offset)
        rtype, rclass, ttl, rdlen = struct.unpack_from("!HHIH", data, offset)
        offset += 10
        rdata = data[offset:offset + rdlen]
        decoded = decode_rdata(rtype, rdata, data, offset)
        return cls(name, rtype, rclass, ttl, rdata, decoded), offset + rdlen

@dataclass
class DNSPacket:
    header: DNSHeader
    questions: list[DNSQuestion] = field(default_factory=list)
    answers: list[DNSAnswer] = field(default_factory=list)
    authority: list[DNSAnswer] = field(default_factory=list)
    additional: list[DNSAnswer | EDNSOptRecord] = field(default_factory=list)

    def add_question(self, question: DNSQuestion):
        self.header.num_questions += 1
        self.questions.append(question)
        return self
    def add_answer(self, answer: DNSAnswer):
        self.header.num_answers += 1
        self.answers.append(answer)
        return self
    def add_additional_rr(self, answer: DNSAnswer | EDNSOptRecord):
        self.header.num_additional_rr += 1
        self.additional.append(answer)
        return self
    def add_authoritive_rr(self, answer: DNSAnswer):
        self.header.num_authority_rr += 1
        self.authority.append(answer)
        return self

    def __bytes__(self):
        offset_map = {}
        out = bytes(self.header)
        for q in self.questions:
            parts = q.qname.rstrip(".").split(".")
            pos = len(out)
            for i in range(len(parts)):
                suffix = ".".join(parts[i:])
                if suffix not in offset_map: offset_map[suffix] = pos
                pos += 1 + len(parts[i].encode())
            pos += 1 # TODO: check if neccessary
            out += bytes(q)
        for section in (self.answers, self.authority, self.additional):
            for record in section: out += record.to_bytes(offset_map, current_offset=len(out))
        return out

    def __str__(self):
        lines = [
            f";; HEADER: id={self.header.transaction_id} {self.header.flags}",
            f";; QUESTION ({self.header.num_questions})",
            *[f"  {q}" for q in self.questions],
            f";; ANSWER ({self.header.num_answers})",
            *[f"  {a}" for a in self.answers],
        ]
        if self.authority: lines += [f";; AUTHORITY ({self.header.num_authority_rr})", *[f"  {a}" for a in self.authority]]
        if self.additional: lines += [f";; ADDITIONAL ({self.header.num_additional_rr})", *[f"  {a}" for a in self.additional]]
        return "\n".join(lines)

    def clear(self):
        self.additional = []
        self.answers = self.authority = []
        self.questions = []
        self.header.num_questions = self.header.num_authority_rr = self.header.num_answers = self.header.num_additional_rr = 0
        self.header.transaction_id += 1
        if self.header.transaction_id > 0xffff: self.header.transaction_id = 0

    @classmethod
    def from_bytes(cls, data: bytes) -> "DNSPacket":
        header = DNSHeader.from_bytes(data)
        offset = 12
        packet = cls(header)

        for _ in range(header.num_questions):
            q, offset = DNSQuestion.from_bytes(data, offset)
            packet.questions.append(q)

        for _ in range(header.num_answers):
            a, offset = DNSAnswer.from_bytes(data, offset)
            packet.answers.append(a)

        for _ in range(header.num_authority_rr):
            a, offset = DNSAnswer.from_bytes(data, offset)
            packet.authority.append(a)

        for _ in range(header.num_additional_rr):
            a, old_offset = DNSAnswer.from_bytes(data, offset)
            if a.type == DNSType.OPT: a, offset = EDNSOptRecord.from_bytes(data, offset)
            else: offset = old_offset
            packet.additional.append(a)

        return packet

    def __len__(self): return len(bytes(self))
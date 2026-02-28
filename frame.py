import struct
from dataclasses import dataclass, field
from const import *
from decode import decode_rdata, decode_name

@dataclass
class DNSHeader_Flags:
    qr: bool
    opcode: int
    aa: bool
    tc: bool
    rd: bool
    ra: bool
    ad: bool
    cd: bool
    rcode: int

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
        opcodes = {0: "QUERY", 1: "IQUERY", 2: "STATUS", 4: "NOTIFY", 5: "UPDATE"}
        rcodes  = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
        return (f"{opcodes.get(self.opcode, self.opcode)} "
                f"{' '.join(flags)} "
                f"{rcodes.get(self.rcode, self.rcode)}")

    @classmethod
    def from_int(cls, value: int) -> "DNSHeader_Flags":
        return cls(
            qr = bool(value >> 15 & 1),
            opcode = value >> 11 & 0b1111,
            aa = bool(value >> 10 & 1),
            tc = bool(value >> 9 & 1),
            rd = bool(value >> 8 & 1),
            ra = bool(value >> 7 & 1),
            ad = bool(value >> 5 & 1),
            cd = bool(value >> 4 & 1),
            rcode = value & 0b1111,
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
    qtype: int | DNSType
    qclass: int | DNSClass

    QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}
    QCLASS = {1: "IN", 3: "CH", 4: "HS", 255: "ANY"}

    def to_bytes(self):
        out = b""
        for part in self.qname.split("."):
            label = part.encode()
            if not label: continue
            if len(label) > 63: raise ValueError(f"DNS label too long: {label}")
            out += struct.pack("!B", len(label)) + label
        out += b"\x00"
        out += struct.pack("!HH", self.qtype if isinstance(self.qtype, int) else self.qtype.value, self.qclass if isinstance(self.qclass, int) else self.qclass.value)
        return out

    def __bytes__(self): return self.to_bytes()
    def __len__(self): return len(bytes(self))

    def __str__(self):
        qtype = self.qtype if isinstance(self.qtype, int) else self.qtype.value
        t = self.QTYPES.get(qtype, str(qtype))

        qclass = self.qclass if isinstance(self.qclass, int) else self.qclass.value
        c = self.QCLASS.get(qclass, str(qclass))
        return f"{self.qname} {t} {c}"

    @classmethod
    def from_bytes(cls, data: bytes, offset: int) -> tuple["DNSQuestion", int]:
        name, offset = decode_name(data, offset)
        qtype, qclass = struct.unpack_from("!HH", data, offset)
        return cls(name, qtype, qclass), offset + 4

@dataclass
class DNSAnswer:
    name: str
    type: int | DNSType
    record_class: int | DNSClass
    ttl: int
    rdata: bytes
    rdata_decoded: str = field(default="", repr=False)

    def encode_name(self, offset_map: dict | None = None, current_offset: int = 0) -> bytes:
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

    def to_bytes(self, offset_map: dict | None = None, current_offset: int = 0):
        name_bytes = self.encode_name(offset_map, current_offset)
        rest = struct.pack("!HHIH", self.type if isinstance(self.type, int) else self.type.value, self.record_class if isinstance(self.record_class, int) else self.record_class.value, self.ttl, len(self.rdata)) + self.rdata
        return name_bytes + rest

    def __bytes__(self): return self.to_bytes()

    def __str__(self):
        type = self.type if isinstance(self.type, int) else self.type.value
        t = TYPES.get(type, str(type))
        return f"{self.name} TTL={self.ttl} {t} {self.rdata_decoded or self.rdata.hex()}"

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
    additional: list[DNSAnswer] = field(default_factory=list)

    def add_question(self, question: DNSQuestion):
        self.header.num_questions += 1
        self.questions.append(question)
        return self
    def add_answer(self, answer: DNSAnswer):
        self.header.num_answers += 1
        self.answers.append(answer)
        return self
    def add_additional_rr(self, answer: DNSAnswer):
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
        self.additional = self.answers = self.authority = []
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
            a, offset = DNSAnswer.from_bytes(data, offset)
            packet.additional.append(a)

        return packet
from enum import Enum

TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}

ROOT_SERVERS = {
    "a.root-servers.net": (["198.41.0.4", "2001:503:ba3e::2:30"]), # Managed by Verisign
    "b.root-servers.net": (["170.247.170.2", "2801:1b8:10::b"]), # Managed by University of Southern California ISI
    "c.root-servers.net": (["192.33.4.12", "2001:500:2::c"]), # Cogent Comms
    "d.root-servers.net": (["199.7.91.13", "2001:500:2d::d"]), # University of Maryland
    "e.root-servers.net": (["192.203.230.10", "2001:500:a8::e"]), # NASA
    "f.root-servers.net": (["192.5.5.241", "2001:500:2f::f"]), # Internet Systems Consortium
    "g.root-servers.net": (["192.112.36.4", "2001:500:12::d0d"]), # US Departament of Defense
    "h.root-servers.net": (["198.97.190.53", "2001:500:1::53"]), # US Army
    "i.root-servers.net": (["192.36.148.17", "2001:7fe::53"]), # Netnod
    "j.root-servers.net": (["192.58.128.30", "2001:503:c27::2:30"]), # Verisign
    "k.root-servers.net": (["193.0.14.129", "2001:7fd::1"]), # RIPE NCC
    "l.root-servers.net": (["199.7.83.42", "2001:500:9f::42"]), # ICANN
    "m.root-servers.net": (["202.12.27.33", "2001:dc3::35"]) # WIDE Project
}

class DNSClass(Enum):
    IN = 1
    CS = 2
    CH = 3
    HS = 4
    ANY = 255

class DNSType(Enum):
    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    PTR = 12
    HINFO = 13
    MX = 15
    TXT = 16
    AAAA = 28
    SRV = 33
    NAPTR = 35
    OPT = 41
    DS = 43
    RRSIG = 46
    NSEC = 47
    DNSKEY = 48
    NSEC3 = 50
    NSEC3PARAM = 51
    TLSA = 52
    CDS = 59
    CDNSKEY = 60
    SVCB = 64
    HTTPS = 65
    TKEY = 249
    TSIG = 250
    IXFR = 251
    AXFR = 252
    ANY = 255
    CAA = 257
from frame import *
import socket
import libcache2 as libcache
import select

class RecursiveDNSResolver:
    def __init__(self) -> None:
        self._packet = DNSPacket(DNSHeader(0, DNSHeader_Flags(False, 0, False, False, True, False, False, False, 0)))
        self.cache = libcache.Cache()
    def _ask_map(self, map: dict, data: bytes):
        socks = []
        for (name, ips) in map.items():
            for ip in ips:
                if not ip: continue
                try:
                    sock = socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_DGRAM)
                    sock.setblocking(False)
                    sock.sendto(data, (ip, 53))
                    socks.append(sock)
                except OSError: pass

        if not socks: raise ConnectionError(f"Could not connect to any server in {map}")

        try:
            readable, _, _ = select.select(socks, [], [], 5.0)
            if not readable: raise ConnectionError("All servers timed out")
            response, _ = readable[0].recvfrom(512)
            return response
        finally:
            for s in socks: s.close()
    def get_ip_from_cache(self, domain: str):
        entries = []
        while True:
            if self.cache.doesElementExist(f"ip:{domain}:{len(entries)}"):
                entries.append(self.cache.getElement(f"ip:{domain}:{len(entries)}"))
            else: break
        return entries
    def get_ns_from_cache(self, domain: str):
        entries = []
        while True:
            if self.cache.doesElementExist(f"ns:{domain}:{len(entries)}"):
                entries.append(self.cache.getElement(f"ns:{domain}:{len(entries)}"))
            else: break
        out_ns_map = {}
        for ns in entries:
            ips = self.get_ip_from_cache(ns)
            out_ns_map[ns] = ips
        return out_ns_map
    def resolve(self, domain: str, resolving: set | None = None):
        if resolving is None: resolving = set()
        if domain in resolving: return []  # cycle detected, give up on this branch
        resolving = resolving | {domain}  # don't mutate the caller's set

        def fetch_ns(d: str, servers: dict):
            self._packet.clear()
            self._packet.add_question(DNSQuestion(d, DNSType.A, DNSClass.IN))
            print("fetch servers", servers)
            parsed = DNSPacket.from_bytes(self._ask_map(servers, bytes(self._packet)))

            ns_names = []
            for i, authority in enumerate(parsed.authority):
                if DNSType(authority.type) != DNSType.NS: continue
                ns_names.append(authority.rdata_decoded)
                print("Saving authority", d, i, authority.rdata_decoded)
                self.cache.saveElement(f"ns:{d}:{i}", authority.rdata_decoded, authority.ttl, deleteifexists=True)
                self.cache.deleteElementIfExists(f"ns:{d}:{i+1}")

            ns_map = {}
            for additional in parsed.additional:
                if additional.name in ns_names:
                    orig_v4, orig_v6 = ns_map.get(additional.name, ([], []))
                    if DNSType(additional.type) == DNSType.A: orig_v4.append((additional.rdata_decoded, additional.ttl))
                    elif DNSType(additional.type) == DNSType.AAAA: orig_v6.append((additional.rdata_decoded, additional.ttl))
                    ns_map[additional.name] = (orig_v4, orig_v6)

            for (ns, (ipv4, ipv6)) in ns_map.items():
                i = 0
                for (ip, ttl) in ipv4 + ipv6:
                    print("Saving", ns, i, ip)
                    self.cache.saveElement(f"ip:{ns}:{i}", ip, ttl, deleteifexists=True)
                    i += 1
            
            out_ns_map = {}
            for ns in ns_names:
                ips = self.get_ip_from_cache(ns)
                if not ips:
                    try: 
                        ips = [i[0] for i in self.resolve(ns, resolving)]
                    except (ConnectionError, RecursionError): pass
                out_ns_map[ns] = ips
            return out_ns_map, parsed
        servers = self.get_ns_from_cache(domain) or ROOT_SERVERS
        print("servers", servers)
        print("resolving", domain)
        while True:
            servers, parsed = fetch_ns(domain, servers)
            if parsed.answers:
                results = []
                for i, answer in enumerate(parsed.answers):
                    if DNSType(answer.type) in (DNSType.A, DNSType.AAAA):
                        results.append((answer.rdata_decoded, answer.ttl))
                        self.cache.saveElement(f"ip:{domain}:{i}", answer.rdata_decoded, answer.ttl, deleteifexists=True)
                    elif DNSType(answer.type) == DNSType.CNAME: 
                        results.extend(self.resolve(answer.rdata_decoded, resolving))
                if results:
                    return results
# import os, traceback
# while True:
#     d = input(">")
#     if d.startswith(">"):
#         print(dns.get_ip_from_cache(d[1:]))
#         continue
#     elif d.startswith("!"):
#         print(dns.get_ns_from_cache(d[1:]))
#         continue
#     # os.system("cls")
#     try: print(dns.resolve(d))
#     except Exception as e:
#         traceback.print_exception(e)
if __name__ == "__main__":    
    import traceback, time
    dns = RecursiveDNSResolver()

    HOST = "0.0.0.0"
    PORT = 53
    BUFFER_SIZE = 512

    out_cache = libcache.Cache()

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind((HOST, PORT))
        s.setblocking(False)
        print(f"UDP server listening on {HOST}:{PORT}")

        while True:
            try:
                data, addr = s.recvfrom(BUFFER_SIZE)
                parsed = DNSPacket.from_bytes(data)
                out = DNSPacket(DNSHeader(parsed.header.transaction_id, DNSHeader_Flags(True, 0, False, False, False, False, False, False, 0)))
                if parsed.header.flags.qr: continue
                if parsed.header.flags.opcode != 0:
                    print("Unhandled opcode:", parsed.header.flags.opcode)
                    continue
                for question in parsed.questions:
                    out.add_question(question)
                    print(question)
                    if DNSClass(question.qclass) != DNSClass.IN or DNSType(question.qtype) != DNSType.A: continue

                    if (count := out_cache.getElement(question.qname, False)):
                        count = int(count)
                        if count > 0:
                            for i in range(count):
                                b: DNSAnswer = out_cache.getElement(f"{question.qname}:{i}", aggressive=False)
                                ttl = out_cache.getRemainingTTL(f"{question.qname}:{i}")
                                if not b: continue
                                if ttl is not None: b.ttl = int(ttl)
                                print(b, ttl)
                                out.add_answer(b)
                            continue
                    else: print("cache miss")

                    max_ttl = 0
                    for i,(a,ttl) in enumerate(dns.resolve(question.qname)):
                        if max_ttl < ttl: max_ttl = ttl
                        aw = DNSAnswer(question.qname, DNSType.A, DNSClass.IN, ttl, socket.inet_aton(a))
                        out.add_answer(aw)
                        out_cache.saveElement(f"{question.qname}:{i}", aw, ttl)
                        out_cache.saveElement(question.qname, i+1, max_ttl, deleteifexists=True)
                s.sendto(bytes(out), addr)
            except BlockingIOError: time.sleep(0.01)
            except Exception as e:
                traceback.print_exception(e)
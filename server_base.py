import traceback, socket, select, struct
from enum import IntEnum
from protocol.frame import DNSPacket, EDNSOptRecord

def is_subdomain(sub: str, parent: str) -> bool:
    sub = sub.rstrip('.').lower()
    parent = parent.rstrip('.').lower()
    return sub == parent or sub.endswith('.' + parent)

def _parse_soa_serial(rdata_decoded: str) -> int | None:
    tokens = rdata_decoded.split()
    params = {k: int(v) for k, v in (t.split("=") for t in tokens[2:])}
    if (d := params.get("serial")): return int(d)
    return None

def query_dns(packet: DNSPacket, server_host: str, buffer_size: int, port: int = 53, timeout: float = 2.0, force_tcp: bool = False) -> DNSPacket:
    packet.add_additional_rr(EDNSOptRecord(False, buffer_size, []))
    if not force_tcp:
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.settimeout(timeout)
        try:
            udp.sendto(bytes(packet), (server_host, port))
            data, _ = udp.recvfrom(buffer_size)
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

class Transport(IntEnum):
    UDP = 0
    TCP = 1
UDP = Transport.UDP
TCP = Transport.TCP

class DNSSocket:
    def _pre_run(self): pass
    def _idle(self): pass
    def _recv_tcp(self, conn: socket.socket) -> bytes | None:
        raw_len = conn.recv(2)
        if len(raw_len) < 2: return None
        msg_len = int.from_bytes(raw_len, "big")

        data = b""
        while len(data) < msg_len:
            chunk = conn.recv(msg_len - len(data))
            if not chunk: return None
            data += chunk
        return data
    def __init__(self, host: str, port: int, tcp_port: int, buffer_size: int) -> None:
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        udp.bind((host, port))
        tcp.bind((host, tcp_port))
        print(f"UDP listening on {host}:{port}")

        tcp.listen(32)
        print(f"TCP listening on {host}:{tcp_port}")

        self.tcp = tcp
        self.udp = udp
        self.buffer_size = buffer_size
    def handle(self, *args, **kwargs) -> bytes: return b""
    def run(self):
        with self.udp as udp, self.tcp as tcp:
            self._pre_run()
            while True:
                try:
                    readable, _, _ = select.select([udp, tcp], [], [], 10)
                    for sock in readable:
                        if sock is udp:
                            data, addr = udp.recvfrom(self.buffer_size)
                            if data: udp.sendto(self.handle(DNSPacket.from_bytes(data), socket.inet_aton(addr[0]), UDP), addr)
                        elif sock is tcp:
                            conn, addr = tcp.accept()
                            with conn:
                                data = self._recv_tcp(conn)
                                if data:
                                    out = self.handle(DNSPacket.from_bytes(data), socket.inet_aton(addr[0]), TCP)
                                    conn.sendall(struct.pack("!H", len(out)) + out)
                    if not readable: self._idle()
                except Exception as e: traceback.print_exception(e)

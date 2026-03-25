import traceback, socket, select, struct
from enum import IntEnum
from protocol.frame import DNSPacket

import tldextract
def is_subdomain(sub, parent):
    sub_ext = tldextract.extract(sub)
    parent_ext = tldextract.extract(parent)

    sub_domain = '.'.join(part for part in [sub_ext.subdomain, sub_ext.domain, sub_ext.suffix] if part)
    parent_domain = '.'.join(part for part in [parent_ext.domain, parent_ext.suffix] if part)

    return sub_domain == parent_domain or sub_domain.endswith("." + parent_domain)

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
    def handle(self, *args, **kwargs): pass
    def run(self):
        with self.udp as udp, self.tcp as tcp:
            self._pre_run()
            while True:
                try:
                    readable, _, _ = select.select([udp, tcp], [], [], 10)
                    for sock in readable:
                        if sock is udp:
                            data, addr = udp.recvfrom(self.buffer_size)
                            if data:
                                out = self.handle(DNSPacket.from_bytes(data), socket.inet_aton(addr[0]), UDP)
                                if out: udp.sendto(out, addr)
                        elif sock is tcp:
                            conn, addr = tcp.accept()
                            with conn:
                                data = self._recv_tcp(conn)
                                if data:
                                    out = self.handle(DNSPacket.from_bytes(data), socket.inet_aton(addr[0]), TCP)
                                    if out: conn.sendall(struct.pack("!H", len(out)) + out)
                    if not readable: self._idle()
                except Exception as e: traceback.print_exception(e)

import struct, socket

def decode_name(data: bytes, offset: int) -> tuple[str, int]:
    labels = []
    visited = set()

    while True:
        if offset in visited: raise ValueError("Compression pointer loop detected")
        visited.add(offset)

        length = data[offset]

        if length == 0:
            offset += 1
            break
        elif (length & 0xC0) == 0xC0:
            # Compression pointer
            pointer = struct.unpack_from("!H", data, offset)[0] & 0x3FFF
            offset += 2
            name, _ = decode_name(data, pointer)
            labels.append(name)
            break
        else:
            offset += 1
            labels.append(data[offset:offset + length].decode())
            offset += length

    return ".".join(labels).lower(), offset

def decode_rdata(rtype: int, rdata: bytes, data: bytes, offset: int) -> str:
    if rtype == 1 and len(rdata) == 4:   # A
        return socket.inet_ntoa(rdata)
    if rtype == 28 and len(rdata) == 16: # AAAA
        return socket.inet_ntop(socket.AF_INET6, rdata)
    if rtype in (2, 5, 12):              # NS, CNAME, PTR — compressed name
        name, _ = decode_name(data, offset)
        return name
    if rtype == 15:                      # MX
        pref = struct.unpack_from("!H", rdata)[0]
        name, _ = decode_name(data, offset + 2)
        return f"{pref} {name}"
    if rtype == 16:                      # TXT
        out, i = [], 0
        while i < len(rdata):
            l = rdata[i]; i += 1
            out.append(rdata[i:i+l].decode(errors="replace")); i += l
        return " ".join(out)
    if rtype == 6:                       # SOA
        mname, o = decode_name(data, offset)
        rname, o = decode_name(data, o)
        serial, refresh, retry, expire, minimum = struct.unpack_from("!IIIII", data, o)
        return f"{mname} {rname} serial={serial} refresh={refresh} retry={retry} expire={expire} min={minimum}"
    return rdata.hex()

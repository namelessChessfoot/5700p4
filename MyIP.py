import socket
from struct import pack, unpack
from checksum import checksum, verify
import random
from collections import deque
import time


def build_ip_header(id, more: bool, fragment_offset, protocol, dst):
    # According to "man 7 raw", with IPPROTO_RAW,
    # checksum, total length, and source ip could be
    # automatically filled.
    version = 4
    ihl = 5
    ver_ihl = (version << 4) + ihl
    tos = 0
    total_length = 0  # For the reason above
    ttl = 64

    flagment = fragment_offset
    if more:
        flagment = flagment | (1 << 13)

    src = 0  # For the reason above
    dst = socket.inet_aton(dst)

    cksum = 0  # For the reason above
    header = pack("!BBHHHBBHL4s", ver_ihl, tos, total_length, id,
                  flagment, ttl, protocol, cksum, src, dst)
    return header


def parse_ip_header(header: bytes):
    # Only returns the fields I concern
    id = 0
    more = False
    protocol = 0
    src = ""
    dst = ""
    _, id, flagment, _, protocol, _, src, dst = unpack(
        "!LHHBBH4s4s", header[:20])
    flags = flagment >> 13
    if flags & 1:
        more = True
    offset = flagment & ((1 << 13)-1)
    src = socket.inet_ntoa(src)
    dst = socket.inet_ntoa(dst)
    return id, more, offset, protocol, src, dst


def ip_send(data: bytes, dst: str, s: socket.socket = None):
    if not s:
        # This is a hack, FIX IT TODO
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    length = len(data)
    mtu = 8*10  # can be optimized
    start = 0
    id = random.randint(0, 60000)
    while start < length:
        end = start + mtu
        packet = build_ip_header(
            id, end < length, start//8, socket.IPPROTO_TCP, dst)+data[start:end]
        res = s.sendto(packet, (dst, 0))
        start = end


def ip_packet_split(packet: bytes):
    # Returns valid split
    ver_ihl = int.from_bytes(packet[:1], "big")
    ver = ver_ihl >> 4
    if ver != 4:
        return None
    ihl = ver_ihl & 0xf
    if ihl < 5:
        return None
    header = packet[:4*ihl]
    data = packet[4*ihl:]
    if not verify(header):
        return None
    ttl = int.from_bytes(header[2:4], "big")
    if ttl != len(packet):
        return None
    return header, data


class IPReceiver():
    def __init__(self, timeout=0.01) -> None:
        self.ip = socket.gethostbyname(f"{socket.gethostname()}.local")
        self.sock = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        self.sock.settimeout(timeout)
        self.container = {}
        self.q = deque()

    def consume(self, id, more, offset, data):
        # each element in container is [length,[(offset,data)...]]
        if id not in self.container:
            self.container[id] = [-1, []]
        self.container[id][1].append((offset*8, data))
        # assume all the offset and data are correct
        if not more:
            self.container[id][0] = offset*8+len(data)
        if self.container[id][0] == -1:
            return None
        self.container[id][1].sort(key=lambda p: p[0])
        l = 0
        for o, d in self.container[id][1]:
            if l != o:
                return None
            l = o+len(d)
        if l != self.container[id][0]:
            return None
        payload = b""
        for o, d in self.container[id][1]:
            payload += d
        self.q.append(payload)
        self.container.pop(id)

    def recv(self, expect_src, timeout):
        start = time.time()
        while time.time()-start < timeout:
            try:
                packet, (ip, port) = self.sock.recvfrom(65535)
                if ip != expect_src:
                    # This is not a packet I am waiting for
                    continue
                res = ip_packet_split(packet)
                if not res:
                    # bad packet TODO
                    continue
                header, data = res
                id, more, offset, protocol, src, dst = parse_ip_header(header)
                if protocol != socket.IPPROTO_TCP:
                    continue
                if src != expect_src or dst != self.ip:
                    continue
                self.consume(id, more, offset, data)
            except socket.timeout:
                break

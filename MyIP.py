import socket
from struct import pack, unpack
from checksum import checksum, verify
import random
from collections import deque
import time
from MyChallenge import EtherSend


class IPSender():
    def __init__(self, dst: str) -> None:
        '''
            Initializes an IPSender object.
            Has a socket and an EtherSend
            By modifying self.take_challenge, the end point that sends bytes can be switched
        '''
        self.ip = socket.gethostbyname(f"{socket.gethostname()}.local")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                  socket.IPPROTO_RAW)
        self.dst = dst
        self.es = EtherSend()
        self.take_challenge = True

    def build_ip_header(self, id: int, more: bool, data_length: int, fragment_offset: int, cksum: int) -> bytes:
        '''
            Builds an IP header
            Parameters:
                All of them are the fields in an IP header
            Returns:
                The header in bytes
        '''
        version = 4
        ihl = 5
        ver_ihl = (version << 4) + ihl
        tos = 0
        total_length = 20 + data_length
        ttl = 64

        flagment = fragment_offset
        if more:
            flagment = flagment | (1 << 13)

        ip = socket.inet_aton(self.ip)
        dst = socket.inet_aton(self.dst)

        header = pack("!BBHHHBBH4s4s", ver_ihl, tos, total_length, id,
                      flagment, ttl, socket.IPPROTO_TCP, cksum, ip, dst)
        return header

    def send(self, data: bytes):
        '''
            Sends data via either socket or EtherSend, depending on self.take_challenge
            Supports splitting a large packet into several small ones
            Parameters:
                data: data in bytes
            Returns:
                none
        '''
        length = len(data)
        mtu = 8*100  # can be optimized
        start = 0
        id = random.randint(0, 65535)
        while start < length:
            end = start + mtu
            payload = data[start:end]

            args = [id, end < length, len(payload), start//8, 0]
            header = self.build_ip_header(*args)
            args[4] = int.from_bytes(checksum(header), "big")
            header = self.build_ip_header(*args)

            packet = header+payload
            if self.take_challenge:
                self.es.ip_send(packet)
            else:
                self.sock.sendto(packet, (self.dst, 0))
            start = end


class IPReceiver():
    def __init__(self, ) -> None:
        '''
            Initializes an IPReceiver object.
            This is a non-block receiver.

            It receives packets with self.recv() and put them into self.container
            It assembles packets with self.consume(). If a packet is completed, it will be put into self.q

            The upperlevel layer can get completed IP packets from self.q
        '''
        self.ip = socket.gethostbyname(f"{socket.gethostname()}.local")
        self.sock = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        self.sock.settimeout(0.0001)
        self.container = {}
        self.q = deque()
        self.last_recv = time.time()

    def consume(self, id: int, more: bool, offset: int, data: bytes):
        '''
            Takes in positional information of packets and assembles them.
            Each element in container is [length,[(offset,data)...]]
            This method assumes that all the incoming data and related information are correct

            Parameters:
                id, more, offset: positional information of data
                data: data in bytes
            Returns:
                none
        '''
        if id not in self.container:
            self.container[id] = [-1, []]
        self.container[id][1].append((offset*8, data))
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

    def parse_ip_header(self, header: bytes):
        '''
            Parse an IP header

            Parameters:
                header: IP header in bytes
            Returns:
                id, more, offset, protocol, src, dst: fields in an IP header if this is a valid IP packet
                none: if this packet is invalid
        '''
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

    def recv(self, expect_src: str, timeout):
        '''
            Receives packets for a while. Packets are given to self.consume()

            Parameters:
                expect_src: as its name
                timeout: the maximum receiving time
            Returns:
                none
        '''
        start = time.time()
        while time.time()-start < timeout:
            try:
                packet, (ip, port) = self.sock.recvfrom(65535)
                if ip != expect_src:
                    # This is not a packet I am waiting for
                    continue
                if time.time()-self.last_recv > 180:
                    print("Connection failed")
                    exit()
                self.last_recv = time.time()
                res = self.ip_packet_split(packet)
                if not res:
                    # bad packet TODO
                    continue
                header, data = res
                id, more, offset, protocol, src, dst = self.parse_ip_header(
                    header)
                if protocol != socket.IPPROTO_TCP:
                    continue
                if src != expect_src or dst != self.ip:
                    continue
                self.consume(id, more, offset, data)
            except socket.timeout:
                break

    def ip_packet_split(self, packet: bytes):
        '''
            Splits an IP packet into a header and a body

            Parameters:
                packet: IP packet in bytes
            Returns:
                header, body: header and body in bytes
        '''
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

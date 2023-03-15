import subprocess
import socket
import fcntl
import struct
import time
from struct import pack, unpack
'''
    This layer is responsible for sending frames to the gateway
    1. I need the MAC of my net device
        1.1 [Solved] How to get the name of my net card? I have enp0s3 and lo
        1.2 Use getHwAddr to get the MAC
    2. I need the MAC of my gateway
        2.1 To get it by broadcasting an ARP request with its IP (How to receive it?)
        2.2 Its IP can be obtained with get_default_gateway
    3. Send
        3.1 I cannot see Preamble, Frame Check Sequence with Wireshark
        3.2 What should be in the content I send?
'''


class EtherSend():
    IPV4 = 0x0800
    ARP = 0x0806

    def __init__(self) -> None:
        self.sock = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        self.sock.settimeout(0.01)
        self.ip = socket.gethostbyname(f"{socket.gethostname()}.local")
        self.gateway = self.get_default_gateway()
        self.device = self.getDeviceName()
        self.mac = self.getHwAddr(self.device)
        self.sock.bind((self.device, 0))
        self.gateway_mac = None
        while self.gateway_mac is None:
            self.arp_send()
            self.gateway_mac = self.arp_recv()

    def get_default_gateway(self):
        '''
            returns the ip address of my gateway in bytes
        '''
        try:
            output = subprocess.check_output(['ip', 'route', 'list', '0/0'])
            gateway = output.split()[2]
            gateway = gateway.decode().split('.')
            gateway = list(map(lambda i: int(i), gateway))
            res = 0
            for i in gateway:
                res <<= 8
                res += i
            return res.to_bytes(4, "big")
        except Exception:
            return None

    def getDeviceName(self):
        try:
            output = subprocess.check_output(['ifconfig', '-a']).decode()
            devices = output.split("\n\n")
            for device in devices:
                if f"inet {self.ip}" in device:
                    colon = device.find(':')
                    if colon != -1:
                        return device[:colon]
        except Exception:
            return None

    def getHwAddr(self, ifname):
        '''
            man netdevice
        '''
        SIOCGIFHWADDR = 0x8927
        info = fcntl.ioctl(self.sock, SIOCGIFHWADDR, struct.pack(
            '256s', bytes(ifname, 'utf-8')[:15]))
        mac = info[18:24]
        return mac

    def buildEtherFrame(self, dst: bytes, data: bytes, type: int) -> bytes:
        frame = pack("!6s6sH", dst, self.mac, type)
        frame += data
        frame += bytes(max(60-len(frame), 0))
        return frame

    def buildARP(self, dst: bytes):
        packet = pack("!HHBBH6s4s6s4s", 1, self.IPV4, 6, 4, 1, self.mac,
                      socket.inet_aton(self.ip), dst, self.gateway)
        return packet

    def arp_send(self):
        dst = bytes.fromhex("ffffffffffff")
        arp = self.buildARP(dst)
        frame = self.buildEtherFrame(dst, arp, self.ARP)
        return self.sock.send(frame)

    def arp_recv(self, timeout=0.5):
        start = time.time()
        while time.time()-start < timeout:
            try:
                packet, address = self.sock.recvfrom(65535)
                ifname, proto = address[:2]
                if ifname != self.device or proto != self.ARP:
                    continue
                if len(address) > 2 and address[2] != socket.PACKET_HOST:
                    continue
                tdts, tsrc, ttype = unpack("!6s6sH", packet[:14])
                if ttype != self.ARP:
                    continue
                _, ptype, _, _, op, sha, _, _, _ = unpack(
                    "!HHBBH6s4s6s4s", packet[14:42])
                if ptype != self.IPV4 or op != 2:
                    continue
                return sha
            except socket.timeout:
                continue

    def ip_send(self, data: bytes):
        if len(data) > 1500:
            print(f"cannot send {len(data)} bytes in an Ethernet Frame")
            return
        frame = self.buildEtherFrame(self.gateway_mac, data, self.IPV4)
        return self.sock.send(frame)


# a = EtherSend()
# print(a.gateway_mac)
# l = [socket.PACKET_HOST, socket.PACKET_BROADCAST, socket.PACKET_MULTICAST,
#      socket.PACKET_OTHERHOST, socket.PACKET_OUTGOING]
# print(l)

# em = "3cbdc5a60333"
# print(bytes.fromhex(em))

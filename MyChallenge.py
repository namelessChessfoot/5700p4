import subprocess
import socket
import fcntl
import struct
import time
from struct import pack, unpack


class EtherSend():
    '''
        1. Sends ARP request
        2. Listens to ARP responses and get the MAC address of the gateway
        3. Sends IP packets wrapped in Ethernet Frames directly to the gateway 
    '''
    IPV4 = 0x0800
    ARP = 0x0806

    def __init__(self) -> None:
        '''
            Initializes required resources, including:
            1. an non-block AF_PACKET socket binded to the default net device,
            2. the MAC address of the gateway
        '''
        self.sock = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        self.sock.settimeout(0.01)
        self.ip = socket.gethostbyname(f"{socket.gethostname()}.local")
        self.gateway = self.get_default_gateway()
        self.device = self.getDeviceName()
        self.mac = self.getHwAddr(self.device)
        self.sock.bind((self.device, 0))
        self.gateway_mac = None

        retry = 3
        while self.gateway_mac is None and retry:
            retry -= 1
            self.arp_send()
            self.gateway_mac = self.arp_recv()
        if self.gateway_mac is None:
            print("Failed to get the MAC address of my gateway")
            exit()

    def get_default_gateway(self) -> bytes:
        '''
            Returns the ip address of my default gateway in bytes
            Parameters:
                none
            Returns:
                The IP of my default gateway
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

    def getDeviceName(self) -> str:
        '''
            Returns the name of my default gateway
            Parameters:
                none
            Returns:
                The name of my default gateway
        '''
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

    def getHwAddr(self, ifname) -> bytes:
        '''
            Returns the MAC of a net device in bytes
            'man netdevice' for more info
            Parameters:
                ifname: the name of the device
            Returns:
                The MAC of the device
        '''
        SIOCGIFHWADDR = 0x8927
        info = fcntl.ioctl(self.sock, SIOCGIFHWADDR, struct.pack(
            '256s', bytes(ifname, 'utf-8')[:15]))
        mac = info[18:24]
        return mac

    def buildEtherFrame(self, dst: bytes, data: bytes, type: int) -> bytes:
        '''
            Builds an Ethernet Frame.
            According to my attempt, Frame Check Sequence and Preamble are not required.
            Parameters:
                dst : the MAC of the destination
                data: user data
                type: Ether Type
            Returns:
                The MAC of my default gateway
        '''
        frame = pack("!6s6sH", dst, self.mac, type)
        frame += data
        frame += bytes(max(60-len(frame), 0))
        return frame

    def buildARP(self, dst: bytes):
        '''
            Builds an ARP request packet.
            Parameters:
                dst: the MAC of the destination
            Returns:
                An ARP request packet
        '''
        packet = pack("!HHBBH6s4s6s4s", 1, self.IPV4, 6, 4, 1, self.mac,
                      socket.inet_aton(self.ip), dst, self.gateway)
        return packet

    def arp_send(self):
        '''
            Sends an ARP request
            Parameters:
                none
            Returns:
                the number of bytes sent
        '''
        dst = bytes.fromhex("ffffffffffff")
        arp = self.buildARP(dst)
        frame = self.buildEtherFrame(dst, arp, self.ARP)
        return self.sock.send(frame)

    def arp_recv(self, timeout=0.5):
        '''
            Listens to ARP responses and captures the one responding to my request.
            Parameters:
                timeout: maximum receiving time
            Returns:
                The MAC address of the gateway
        '''
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
                _, ptype, _, _, op, sha, spa, _, _ = unpack(
                    "!HHBBH6s4s6s4s", packet[14:42])
                if ptype != self.IPV4 or op != 2 or spa != self.gateway:
                    continue
                return sha
            except socket.timeout:
                continue

    def ip_send(self, data: bytes):
        '''
            Sends an IP packet via Ethernet
            Parameters:
                data:  data no more than 1500 bytes
            Returns:
                the number of bytes sent
        '''
        if len(data) > 1500:
            print(f"cannot send {len(data)} bytes in an Ethernet Frame")
            return
        frame = self.buildEtherFrame(self.gateway_mac, data, self.IPV4)
        return self.sock.send(frame)

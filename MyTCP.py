from SendBuffer import SendBuffer
from struct import pack, unpack
import socket
from checksum import checksum, verify
from MyIP import IPReceiver, IPSender
import random
import time
from collections import deque


class TCP():
    mod = 1 << 32

    def __init__(self, ip: str, port: int) -> None:
        self.receiver = IPReceiver()
        self.ips = IPSender(ip)
        self.dst_ip = ip
        self.dst_port = port
        self.src_ip = socket.gethostbyname(f"{socket.gethostname()}.local")

    def build_tcp_pseudo_header(self, tcp_packet_length):
        me = socket.inet_aton(self.src_ip)
        peer = socket.inet_aton(self.dst_ip)
        pheader = pack("!4s4sBBH", me, peer, 0,
                       socket.IPPROTO_TCP, tcp_packet_length)
        return pheader

    def build_tcp_header(self, seqnum, acknum, offset, control, window, cksum):
        urg, ack, psh, rst, syn, fin = control
        control = (urg << 5)+(ack << 4)+(psh << 3)+(rst << 2)+(syn << 1)+fin
        offset <<= 4
        header = pack("!HHIIBBHHH",
                      self.src_port,
                      self.dst_port,
                      seqnum % self.mod,
                      acknum % self.mod,
                      offset,
                      control,
                      window,
                      cksum,
                      0)
        return header

    @classmethod
    def get_raw_number(cls, relative, last):
        lo = relative
        while lo+cls.mod < last:
            lo += cls.mod
        hi = lo+cls.mod
        return hi if abs(hi-last) < abs(lo-last) else lo

    def parse_tcp_packet(self, packet: bytes):
        # split packet into header+data, and parse header
        # returns what I need only
        sp, dp, seq, ack, offset, control, window, cksum, _ = unpack(
            "!HHLLBBHHH", packet[:20])
        offset >>= 4
        ph = self.build_tcp_pseudo_header(len(packet))
        if not verify(ph+packet):
            print(f"Bad packet, seq={seq}, cksum={cksum}")
            return None  # TODO
        data = packet[4*offset:]
        seq = self.get_raw_number(seq, self.server_seq)
        ack = self.get_raw_number(ack, self.server_ack)
        return (sp, dp, seq, ack,
                ((control >> 5) & 1,
                 (control >> 4) & 1,
                 (control >> 3) & 1,
                 (control >> 2) & 1,
                 (control >> 1) & 1,
                 (control >> 0) & 1),
                window), data

    def send(self, data: bytes, control, seq=None):
        if seq is None:
            seq = self.my_seq
        wd = 65535
        args = [seq, self.my_ack, 5, control, wd, 0]
        header = self.build_tcp_header(*args)

        ph = self.build_tcp_pseudo_header(len(header+data))
        args[5] = int.from_bytes(checksum(ph+header+data), "big")
        header = self.build_tcp_header(*args)
        packet = header+data
        self.ips.send(packet)

    def connect(self):
        self.my_seq = self.server_ack = random.randint(0, self.mod-1)
        self.my_ack = self.server_seq = 0
        while True:
            self.send(b"", (0, 0, 0, 0, 1, 0))
            start = time.time()
            while len(self.receiver.q) == 0 and time.time()-start < 3:
                self.receiver.recv(self.dst_ip, 0.2)
            synced = False
            while len(self.receiver.q) and not synced:
                packet = self.receiver.q.popleft()
                res = self.parse_tcp_packet(packet)
                if res is None:
                    continue
                (sp, dp, seq, ack, control, window), data = res
                if sp != self.dst_port or dp != self.src_port:
                    continue
                u, a, p, r, s, f = control
                if (not a) or (not s):
                    continue
                if ack != self.my_seq+1:
                    continue
                self.my_ack = self.server_seq = seq+1
                self.my_seq = self.server_ack = self.my_seq + 1
                synced = True
            if synced:
                break
        self.send(b"", (0, 1, 0, 0, 0, 0))

    def tcp_process(self, data_out: bytes):
        self.src_port = random.randint(5000, 60000)
        print(f"port = {self.src_port}")

        self.connect()

        next_ack = self.my_ack
        my_fin, server_fin = False, False

        send_buf = SendBuffer()
        recv_buf = {}
        ret = []
        pending_sends = deque([data_out])
        cwnd = 1

        downloaded_bytes = 0
        start = last = time.time()
        while (not my_fin) or (not server_fin) or self.my_ack < next_ack or len(pending_sends) or send_buf.size():
            if time.time()-last > 3:
                last = time.time()
                print(
                    f"total {int(last-start)} {downloaded_bytes/1024}KB downloaded, cwnd={cwnd}, sb={send_buf.size()}")
            # send
            # receive and consume
            while (len(pending_sends) and send_buf.size() < cwnd) or self.my_ack < next_ack:
                # first trans of normal data or ACK
                data = b""
                if (len(pending_sends) and send_buf.size() < cwnd):
                    data = pending_sends.popleft()
                control = (0, 1, 0, 0, 0, 0)
                self.my_ack = max(next_ack, self.my_ack)
                self.send(data, control)
                if len(data):
                    # pure ACK doesnt have to be confirmed
                    send_buf.push(self.my_seq+len(data),
                                  (self.my_seq, data, control))
                self.my_seq += len(data)

            if len(pending_sends) == 0 and (not my_fin):
                # first trans of fin
                control = (0, 1, 0, 0, 0, 1)
                self.send(b"", control)
                send_buf.push(self.my_seq+1, (self.my_seq, b"", control))
                self.my_seq += 1
                my_fin = True

            while send_buf.should_send() or (my_fin and server_fin and send_buf.size()):
                ack, seq, data, control = send_buf.get()
                if self.server_ack >= ack:
                    send_buf.confirm(ack)
                else:
                    print(f"resend {seq}")
                    cwnd = 1
                    self.send(data, control, seq)

            self.receiver.recv(self.dst_ip, 0.001)
            while len(self.receiver.q):
                packet = self.receiver.q.popleft()
                res = self.parse_tcp_packet(packet)
                if res is None:
                    continue
                (sp, dp, seq, ack, control, window), data_in = res
                if sp != self.dst_port or dp != self.src_port:
                    continue
                if self.server_seq <= seq:
                    recv_buf[seq] = (ack, control, window, data_in)
                else:
                    self.my_ack -= 1

            while self.server_seq in recv_buf:
                (ack, control, window, data_in) = recv_buf.pop(self.server_seq)
                if len(data_in):
                    ret.append(data_in)
                    downloaded_bytes += len(data_in)
                self.server_seq += len(data_in)
                u, a, p, r, s, f = control
                if a:
                    self.server_ack = max(self.server_ack, ack)
                    send_buf.confirm(ack)
                    cwnd = min(cwnd+1, 1000)
                if f:
                    self.server_seq += 1
                    server_fin = True
                next_ack = max(next_ack, self.server_seq)
        print(f"done! {time.time()-start}s")
        return ret

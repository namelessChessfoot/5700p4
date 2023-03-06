import socket
from struct import pack, unpack
import time
from checksum import checksum, verify
from MyIP import ip_send, IPReceiver
import random
from datetime import datetime
from collections import deque
import heapq


def build_tcp_header(sp, dp, seqnum, acknum, offset, urg, ack, psh, rst, syn, fin, window, cksum, urptr):
    control = (urg << 5)+(ack << 4)+(psh << 3)+(rst << 2)+(syn << 1)+fin
    offset <<= 4
    header = pack("!HHIIBBHHH", sp, dp, seqnum, acknum,
                  offset, control, window, cksum, urptr)
    return header


def parse_tcp_packet(packet: bytes, peer):
    # split packet into header+data, and parse header
    # returns what I need only
    sp, dp, seq, ack, offset, control, window, _, _ = unpack(
        "!HHLLBBHHH", packet[:20])
    offset >>= 4
    ph = build_tcp_pseudo_header(peer, len(packet))
    if not verify(ph+packet):
        return None  # TODO
    data = packet[4*offset:]
    return (sp, dp, seq, ack,
            ((control >> 5) & 1,
             (control >> 4) & 1,
             (control >> 3) & 1,
             (control >> 2) & 1,
             (control >> 1) & 1,
             (control >> 0) & 1),
            window), data


def build_tcp_pseudo_header(peer, tcp_packet_length):
    me = socket.gethostbyname(f"{socket.gethostname()}.local")
    me = socket.inet_aton(me)
    peer = socket.inet_aton(peer)
    pheader = pack("!4s4sBBH", me, peer, 0,
                   socket.IPPROTO_TCP, tcp_packet_length)
    return pheader


def connect(src_port, dst_ip, dst_port, receiver: IPReceiver):
    my_seq = random.randint(0, 1e9)
    server_seq = 0
    while True:
        tcp_simple_send(b"", src_port, dst_ip, dst_port,
                        (0, 0, 0, 0, 1, 0), my_seq, server_seq)
        start = time.time()
        while len(receiver.q) == 0 and time.time()-start < 3:
            receiver.recv(dst_ip, 0.2)
        synced = False
        while len(receiver.q) and not synced:
            packet = receiver.q.popleft()
            res = parse_tcp_packet(packet, dst_ip)
            if res is None:
                continue
            (sp, dp, seq, ack, control, window), data = res
            if sp != dst_port or dp != src_port:
                continue
            u, a, p, r, s, f = control
            if (not a) or (not s):
                continue
            if ack != my_seq+1:
                continue
            server_seq = seq+1
            my_seq += 1
            synced = True
        if synced:
            break
    tcp_simple_send(b"", src_port, dst_ip, dst_port,
                    (0, 1, 0, 0, 0, 0), my_seq, server_seq)
    return my_seq, server_seq, server_seq, my_seq


class SendBuffer():
    delay = 3

    def __init__(self) -> None:
        self.pq = []
        self.buf = {}

    def push(self, seq, data):
        heapq.heappush(self.pq, (time.time(), seq))
        self.buf[seq] = data

    def clear(self):
        while len(self.pq) and self.pq[0][1] not in self.buf:
            heapq.heappop(self.pq)

    def confirm(self, seq):
        if seq in self.buf:
            self.buf.pop(seq)
            self.clear()

    def size(self):
        return len(self.buf)

    def get(self):
        seq = heapq.heappop(self.pq)[1]
        data = self.buf[seq]
        heapq.heappush(self.pq, (time.time(), seq))
        self.clear()
        return seq, data

    def should_send(self):
        return len(self.buf) and time.time()-self.pq[0][0] > self.delay


def tcp_process(data_out: bytes, dst_ip: str, dst_port: int):
    # src_port = random.randint(5000, 60000)
    src_port = 12345  # teardown test
    print(src_port)
    receiver = IPReceiver()
    res = connect(src_port, dst_ip, dst_port, receiver)
    if not res:
        print("Connect failed")
        return
    my_seq, server_seq, my_ack, server_ack = res
    my_fin, server_fin = False, False

    def send(data, control, seq, ack):
        # helper func for avoiding duplicate code
        tcp_simple_send(data, src_port, dst_ip, dst_port, control, seq, ack)
    ptr = 0
    send_buf = SendBuffer()
    recv_buf = {}
    ret = []
    debug_bc = 0
    pending_acks = deque()
    pending_sends = deque([data_out])
    start = last = time.time()
    while (not my_fin) or (not server_fin) or len(pending_acks) or len(pending_sends) or send_buf.size():
        if time.time()-last > 3:
            last = time.time()
            print(f"total {int(last-start)} {debug_bc/1024}KB downloaded")
        # send
        # receive and consume
        while len(pending_sends) or len(pending_acks):
            # first trans of normal data or ACK
            data = b""
            ack = my_ack
            if len(pending_sends):
                data = pending_sends.popleft()
            if len(pending_acks):
                ack = pending_acks.popleft()
            control = (0, 1, 0, 0, 0, 0)
            send(data, control, my_seq, ack)
            my_ack = max(ack, my_ack)
            if len(data):
                # pure ACK doesnt have to be confirmed
                send_buf.push(my_seq+len(data), (my_seq, data, control))
            my_seq += len(data)

        if len(pending_sends) == 0 and (not my_fin):
            # first trans of fin
            control = (0, 1, 0, 0, 0, 1)
            send(b"", control, my_seq, my_ack)
            send_buf.push(my_seq+1, (my_seq, b"", control))
            my_seq += 1
            my_fin = True

        while send_buf.should_send():
            ack_seq, (seq, data, control) = send_buf.get()
            print(f"resend {seq}")
            send(data, control, seq, my_ack)

        receiver.recv(dst_ip, 0.2)
        while len(receiver.q):
            packet = receiver.q.popleft()
            res = parse_tcp_packet(packet, dst_ip)
            if res is None:
                continue
            (sp, dp, seq, ack, control, window), data_in = res
            if sp != dst_port or dp != src_port:
                continue
            if server_seq <= seq:
                recv_buf[seq] = (ack, control, window, data_in)
            else:
                pending_acks.append(seq+len(data_in))

        while server_seq in recv_buf:
            server_seq_ini = server_seq
            (ack, control, window, data_in) = recv_buf.pop(server_seq)
            if len(data_in):
                ret.append(data_in)
                debug_bc += len(data_in)
            server_seq += len(data_in)
            u, a, p, r, s, f = control
            if a:
                server_ack = max(server_ack, ack)
                send_buf.confirm(ack)
            if f:
                server_seq += 1
                server_fin = True
            if server_seq != server_seq_ini:
                pending_acks.append(server_seq)
    print(f"done! {time.time()-start}s")
    return ret


def tcp_simple_send(data: bytes, src_port: int, dst_ip: str, dst_port: int, control, seq, ack):
    header = build_tcp_header(
        src_port, dst_port, seq, ack, 5, *control, 2000, 0, 0)
    ph = build_tcp_pseudo_header(dst_ip, len(header+data))
    header = build_tcp_header(
        src_port, dst_port, seq, ack, 5, *control, 2000, int.from_bytes(checksum(ph+header+data), "big"), 0)
    packet = header+data
    ip_send(packet, dst_ip)


test = "204.44.192.60"
# domain = "david.choffnes.com"
tcp_process(b"Hello world, this is Keming Xu", test, 80)

# packet = bytes.fromhex("00501767c4d30cc712f7c1b05018721000000000c46cbb0dfc9984278bb081f4de9ccb23d5b8a07b6f212e9fd11ee88b1a6104bea027c4106ef80677542852b4cf693aadb5fec0fb52013803a2b3b0af24db0a1bd2de5d97715d4f56339877399d9623d39efd1fc0d9de69a843a39528c68efa11246f001a49035a02002973adb33ee4a9594bdaa4dd0b6d8932a6c427c299cbb6c398218d68a7cf3b6f0cd0e24f0cbdaedf3fb43971851a2ffbad88d418e7ca68010ad0b60974782cbe9861781540f8025c45f6c97291478e9254a90e74767410fa6c9e21831a213d69181500cb51b74c2f57e0631e97e30390c54aaa561ce7c6dce0021054b0744c2664774dfc9d3219fbc12f87240fabd4f6df39d547cf7be2db511cab0b45a524427e4cb34f26d57fb4779c5de538460d65b9394fa59df51edca08ef822536983df4a06be39c6b264d9a4f2a66136a723742481251a0205ecd87188a5e5ea0118f59a2c7d3186fe0c591049a42f96dba20331fe7eedb60fb3a0bd3a1b20d4fdfc19b3ac4dcae20439939ca4ba16adf71bf802ce8cc8cdae7b7db9e8b90beaaba546e2f76efbbff5e41984aed2cf210e78dc1cdb6bf56057fff36c108ff1364eb2b513a36388ab3081e761c2f57d46a87b0b0a4f2d9849eb8e6424535ad87d229fbd95d8109f66f17aa20bd42458eef40609a0c8ccb0216205adee5c176a1e4d8439df0e2238d858da9eaff53719f5d4ddeae874c8e00a386cc5c830cf50933fa8c5b566b6ab10f8012332e00b6375d1e7a4fae7f45e6dceae8c66cbb412ff7894aa60c9b7d503c126f67836712ccb8f7e58eb47ce187481148c9ee51d6c76ffffc74d83fe43db9b780833955c4bf6c1e5ac93efae4c53f0182d6fa0cea0c4d101aeb103e948f93f4674c23b58bcaa72d0e0c4a3cef18064befac4594099522d2e31ffe6ebbdb52241ce2a6878b5501fd073933a2c31cd370119f1f4b7baf0a2cb82728693580e88f0ef951901338c275699fd4e4cc205e02c7d2faee33807fae7b77dcc5a8580019b7015bc7ce30ff35f9ab6c280612d30b6293472ccecd1c5597f184547b465f3aa56b7d99ec7ad5deee37ace1f54a4a3fed48def2856b584986f1ff7e38a52f1a47397947dca1477dc2ee8d068c067786ff3f31c5723c96218bd2ca5264289d006df312539ffdf58d0145767aed06f4d218e700e7aa46006c9c0bc73c6025182e6fe63e94f3aa1e60069071fadb3fb7a78ad32bca226a5d370af824e3398a6836941930ee3b1ce112e2543f157b1432060f18d5a3480885ff9d0a51694f10a9af3b562db378635c268e06a1030421c2491d85561b4a766c1b5cb745975d180f40596adb5d41cd762683d7f1796cfeced60b6ba451e9427c7cbbeb030949cb6d925d00a9fa2a6d5d7d8f560ddddbb77fcd009937fa52156c5e6d43d18a0a38d61ad80562647ebd3fdf23cb49899b84d252997cda81f60bfff814ddc86f2d0c5e31ec54287f1b31e2c01b71c47f82493c083131c546d58193e40737b75e1bea311d2")
# ph = build_tcp_pseudo_header(test, len(packet))
# print(f"TCP packet length: {len(packet)}")
# print(checksum(ph+packet))

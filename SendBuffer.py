import heapq
import time


class SendBuffer():
    delay = 60

    def __init__(self) -> None:
        self.pq = []
        self.buf = {}

    def push(self, expect_ack, data):
        heapq.heappush(self.pq, (time.time(), expect_ack))
        self.buf[expect_ack] = data

    def clear(self):
        while len(self.pq) and self.pq[0][1] not in self.buf:
            heapq.heappop(self.pq)

    def confirm(self, ack):
        if ack in self.buf:
            self.buf.pop(ack)
            self.clear()

    def size(self):
        return len(self.buf)

    def get(self):
        ack = heapq.heappop(self.pq)[1]
        data = self.buf[ack]
        heapq.heappush(self.pq, (time.time(), ack))
        self.clear()
        return ack, *data

    def should_send(self):
        return len(self.buf) and time.time()-self.pq[0][0] > self.delay

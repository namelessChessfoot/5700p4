import heapq
import time


class SendBuffer():
    '''
        A data structure that keeps data.
        Has a priority queue and a dict.
        The dict keeps these unconfirmed data. Data can be confirmed with its key in the dict.
        The priority queue sorts data by the time they are pushed.

        When a data is confirmed, this data structure uses a lazy strategy to remove the related entry:
        Only the entry in the dict is removed immediately within O(1) time,
        the entry in the priority queue will be removed when it is at the top of the queue.
    '''
    delay = 60

    def __init__(self) -> None:
        '''
            Initializes itself with a priority queue and a dict
        '''
        self.pq = []
        self.buf = {}

    def push(self, expect_ack, data):
        '''
            Keeps a price of data and the number used to confirm it.
            Parameters:
                expect_ack: the number that confirms data
                data: as its name
            Returns:
                none
        '''
        heapq.heappush(self.pq, (time.time(), expect_ack))
        self.buf[expect_ack] = data

    def clear(self):
        '''
            Removes the entries at the top of the priority queue if they are not in the dict
            Parameters:
                none
            Returns:
                none
        '''
        while len(self.pq) and self.pq[0][1] not in self.buf:
            heapq.heappop(self.pq)

    def confirm(self, ack):
        '''
            Confirm a piece of data with an ACK number
            Parameters:
                ack: the ACK number
            Returns:
                none
        '''
        if ack in self.buf:
            self.buf.pop(ack)
            self.clear()

    def size(self):
        '''
            Parameters:
                none
            Returns:
                The size of itself
        '''
        return len(self.buf)

    def get(self):
        '''
            Get the first data in the priority queue
            Parameters:
                none
            Returns:
                ack: the number used to confirm the data
                data: the data
        '''
        ack = heapq.heappop(self.pq)[1]
        data = self.buf[ack]
        heapq.heappush(self.pq, (time.time(), ack))
        self.clear()
        return ack, data

    def should_send(self):
        '''
            Parameters:
                none
            Returns:
                Whether some data should be resent
        '''
        return len(self.buf) and time.time()-self.pq[0][0] > self.delay

from spiral.curvecp.pynacl._dna_pb2 import WhiskerTree, Memory


class Remy(object):
    def __init__(self, dnaString):
        self.tree = WhiskerTree()
        self.tree.ParseFromString(dnaString)
        self.rttAverage = None
        self.deltaAverage = 0
        self.lastReceivedAt = None
        self.rttMin = None
        self.window = 0
        self.secPerMessage = 0
        self.lastSentAt = 0
        self.rttTimeout = 10

    def processDelta(self, now, rtt):
        if self.rttAverage is None:
            self.rttMin = self.rttAverage = rtt
        else:
            self.rttAverage = (rtt * .125) + (self.rttAverage * .875)
            delta = now - self.lastReceivedAt
            self.deltaAverage = (delta * .125) + (self.deltaAverage * .875)
            self.rttMin = min(rtt, self.rttMin)
        ratio = rtt / self.rttMin if self.rttMin else 1
        print rtt, self.rttMin, ratio
        whisker = self._findWhisker(self.deltaAverage, 0, ratio)
        print whisker
        self.window = whisker.window_increment + self.window * whisker.window_multiple
        self.secPerMessage = whisker.intersend
        self.rttTimeout = self.secPerMessage * self.window
        self.lastReceivedAt = now

    def writerow(self, now, fobj):
        import csv
        csv.writer(fobj).writerow(
            (now, self.rttAverage, self.rttMin, self.window, self.secPerMessage, self.rttTimeout))

    def _memoryContainedBy(self, m, mr):
        return (mr.lower.rec_rec_ewma <= m.rec_rec_ewma <= mr.upper.rec_rec_ewma
                and mr.lower.rec_send_ewma <= m.rec_send_ewma <= mr.upper.rec_send_ewma
                and mr.lower.rtt_ratio <= m.rtt_ratio <= mr.upper.rtt_ratio)

    def _findWhisker(self, ackAverage, sendAverage, rttRatio):
        memory = Memory(rec_rec_ewma=ackAverage, rec_send_ewma=sendAverage, rtt_ratio=rttRatio)
        node = self.tree
        while True:
            if node.HasField('leaf') and self._memoryContainedBy(memory, node.leaf.domain):
                return node.leaf
            for child in node.children:
                if self._memoryContainedBy(memory, child.domain):
                    node = child
                    break
            else:
                raise ValueError('no nodes found for %s' % (memory,))

    def timedOut(self, now):
        pass

    def nextMessageIn(self, now):
        return max(self.lastSentAt + self.secPerMessage - now, 0)

    def nextTimeoutIn(self, now, qd):
        if not qd.sentAt:
            return self.rttTimeout
        ret = now - qd.sentAt[-1] + self.rttTimeout
        assert ret > 0
        return ret

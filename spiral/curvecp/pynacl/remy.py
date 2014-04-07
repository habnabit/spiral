from __future__ import division

import os

from spiral.curvecp.pynacl._dna_pb2 import WhiskerTree, Memory


ALPHA = 1 / 8
SLOW_ALPHA = 1 / 256
HERE = os.path.dirname(os.path.abspath(__file__))


class Remy(object):
    def __init__(self):
        self.tree = WhiskerTree()
        with open(os.path.join(HERE, 'remy.out.0')) as infile:
            self.tree.ParseFromString(infile.read())
        self.lastReceivedAt = None
        self.rttMin = None
        self.recEWMA = 0
        self.slowRecEWMA = 0
        self.window = 0
        self.secPerMessage = 0
        self.lastSentAt = 0
        self.rttTimeout = 10

    def processDelta(self, now, rtt):
        if self.rttMin is None:
            self.rttMin = self.rttEWMA = rtt
        else:
            delta = now - self.lastReceivedAt
            self.recEWMA = (1 - ALPHA) * self.recEWMA + ALPHA * delta
            self.slowRecEWMA = (1 - SLOW_ALPHA) * self.slowRecEWMA + SLOW_ALPHA * delta
            self.rttMin = min(rtt, self.rttMin)
        ratio = rtt / self.rttMin if self.rttMin else 1
        whisker = self._findWhisker(self.recEWMA, self.slowRecEWMA, ratio)
        self.window = whisker.window_increment + self.window * whisker.window_multiple
        self.secPerMessage = whisker.intersend / 1000
        self.rttTimeout = self.secPerMessage * self.window
        self.lastReceivedAt = now

    def writerow(self, now, fobj):
        import csv
        csv.writer(fobj).writerow(
            (now, self.recEWMA, self.slowRecEWMA, self.rttMin, self.window, self.secPerMessage, self.rttTimeout))

    def _memoryContainedBy(self, m, mr):
        return (mr.lower.rec_rec_ewma <= m.rec_rec_ewma <= mr.upper.rec_rec_ewma
                and mr.lower.slow_rec_rec_ewma <= m.slow_rec_rec_ewma <= mr.upper.slow_rec_rec_ewma
                and mr.lower.rtt_ratio <= m.rtt_ratio <= mr.upper.rtt_ratio)

    def _findWhisker(self, recEWMA, slowRecEWMA, rttRatio):
        memory = Memory(
            rec_rec_ewma=recEWMA, slow_rec_rec_ewma=slowRecEWMA,
            rec_send_ewma=0, rtt_ratio=rttRatio)
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

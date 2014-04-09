from __future__ import division

import random
import time


class Chicago(object):
    def __init__(self):
        self.rttAverage = 0
        self.rttLastSpeedAdjustment = time.time()
        self.rttLastEdge = self.rttLastDoubling = 0
        self.rttTimeout = 1
        self.rttPhase = 0
        self.rttSeenOlderHigh = self.rttSeenOlderLow = False
        self.rttLastPanic = 0
        self.secPerMessage = 0
        self.lastSentAt = 0
        self.window = None

    def writerow(self, now, fobj):
        import csv
        csv.writer(fobj).writerow((now, self.rttTimeout, self.secPerMessage,
                                   self.rttAverage, self.rttHighwater, self.rttLowwater))

    def processDelta(self, now, rtt):
        if not self.rttAverage:
            self.secPerMessage = rtt
            self.rttAverage = rtt
            self.rttDeviation = rtt / 2
            self.rttHighwater = rtt
            self.rttLowwater = rtt

        rttDelta = rtt - self.rttAverage
        self.rttAverage += rttDelta / 8
        rttDelta = abs(rttDelta)
        rttDelta -= self.rttDeviation
        self.rttDeviation += rttDelta / 4
        self.rttTimeout = self.rttAverage + 4 * self.rttDeviation
        self.rttTimeout += 8 * self.secPerMessage

        rttDelta = rtt - self.rttHighwater
        self.rttHighwater += rttDelta / 1024
        rttDelta = rtt - self.rttLowwater
        if rttDelta > 0:
            self.rttLowwater += rttDelta / 8192
        else:
            self.rttLowwater += rttDelta / 256

        if now < self.rttLastSpeedAdjustment + 16 * self.secPerMessage:
            self._finalRttAdjustments(now)
            return

        if now - self.rttLastSpeedAdjustment > 10:
            self.secPerMessage = 1 + random.random() * .125
        if self.secPerMessage >= 0.000131072:
            t = self.secPerMessage
            if self.secPerMessage < 0.016777216:
                self.secPerMessage = t - 444.0892 * t ** 3
            else:
                self.secPerMessage = t / (1 + t ** 2 / 444.0892)
        self.rttLastSpeedAdjustment = now

        if self.rttPhase == 0:
            if self.rttSeenOlderHigh:
                self.rttPhase = 1
                self.rttLastEdge = now
                self.secPerMessage += self.secPerMessage * random.random() * 0.25
            elif self.rttSeenOlderLow:
                self.rttPhase = 0

        self.rttSeenOlderHigh = self.rttSeenOlderLow = False
        if self.rttAverage > self.rttHighwater + 0.005:
            self.rttSeenOlderHigh = True
        elif self.rttAverage < self.rttLowwater:
            self.rttSeenOlderLow = True

        self._finalRttAdjustments(now)

    def _finalRttAdjustments(self, now):
        if now - self.rttLastEdge < 60:
            if now < self.rttLastDoubling + 4 * self.secPerMessage * 64 + self.rttTimeout + 5:
                return
        elif now < self.rttLastDoubling + 4 * self.secPerMessage + 2 * self.rttTimeout:
            return
        elif self.secPerMessage <= 0.000066:
            return

        self.secPerMessage /= 2
        self.rttLastDoubling = now
        if self.rttLastEdge:
            self.rttLastEdge = now

    def nextMessageIn(self, now):
        return max(self.lastSentAt + self.secPerMessage - now, 0)

    def nextTimeoutIn(self, now, qd):
        if not qd.sentAt:
            return self.rttTimeout
        ret = now - qd.sentAt[-1] + self.rttTimeout
        assert ret > 0
        return ret

    def timedOut(self, now):
        if now > self.rttLastPanic + 4 * self.rttTimeout:
            self.secPerMessage *= 2
            self.rttLastPanic = now
            self.rttLastEdge = now

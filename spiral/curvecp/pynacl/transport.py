from __future__ import division

import os
from random import SystemRandom, random
import struct
import time

from blist import sortedlist
from interval import IntervalSet
from nacl.public import PublicKey, PrivateKey, Box
from twisted.internet import defer
from twisted.internet.protocol import DatagramProtocol

from spiral.curvecp.pynacl.interval import halfOpen
from spiral.curvecp.pynacl.message import _Message, messageParser


sysrandom = SystemRandom()


class CurveCPTransport(DatagramProtocol):
    def __init__(self, host, port, serverKey, serverExtension, clientKey=None, clientExtension='\x00' * 16):
        self.host = host
        self.port = port
        self.serverKey = serverKey
        self.serverExtension = serverExtension
        if clientKey is None:
            clientKey = PrivateKey.generate()
        self.clientKey = clientKey
        self.clientExtension = clientExtension
        self.awaiting = 'cookie'
        self._received = IntervalSet()
        self._weAcked = IntervalSet()
        self._sent = IntervalSet()
        self._theyAcked = IntervalSet()
        self.outbuffer = []
        self.received = bytearray()
        self.previousID = 0
        self.fragment = sortedlist()
        self.rttAverage = 0
        self.rttLastSpeedAdjustment = time.time()
        self.rttLastEdge = self.rttLastDoubling = 0
        self.rttTimeout = 1
        self.rttPhase = 0
        self.rttSeenOlderHigh = self.rttSeenOlderLow = False
        self.secPerMessage = 1
        self.lastMessage = 0
        self.sentMessageAt = {}
        self.delayedCall = None

    def nextNonce(self):
        self._nonce = (self._nonce + 1) % (2 ** 64)

    @property
    def _packed_nonce(self):
        return struct.pack('!Q', self._nonce)

    def _full_nonce(self, which):
        return 'CurveCP-client-' + which + self._packed_nonce

    def startProtocol(self):
        self._nonce = sysrandom.randrange(2 ** 64)
        self._key = PrivateKey.generate()
        self._box = Box(self._key, self.serverKey)
        packet = (
            'QvnQ5XlH'
            + self.serverExtension
            + self.clientExtension
            + str(self._key.public_key)
            + '\x00' * 64
            + self._packed_nonce
            + self._box.encrypt('\x00' * 64, self._full_nonce('H')).ciphertext)
        self.transport.write(packet, (self.host, self.port))

    def datagramReceived(self, data, host_port):
        meth = getattr(self, 'datagram_' + self.awaiting)
        meth(data)

    def datagram_cookie(self, data):
        assert len(data) == 200
        assert data[:8] == 'RL3aNMXK'
        assert data[8:24] == self.clientExtension
        assert data[24:40] == self.serverExtension
        nonce = data[40:56]
        data = self._box.decrypt(data[56:200], 'CurveCPK' + nonce)
        self._serverShortKey = PublicKey(data[:32])
        self._box = Box(self._key, self._serverShortKey)
        self._cookie = data[32:144]
        message = '\0' * 192
        nonce = os.urandom(16)
        longLongBox = Box(self.clientKey, self.serverKey)
        initiatePacket = (
            str(self.clientKey.public_key)
            + nonce
            + longLongBox.encrypt(str(self._key.public_key), 'CurveCPV' + nonce).ciphertext
            + "\aexample\003com".ljust(256, '\x00')
            + message)
        self.nextNonce()
        packet = (
            'QvnQ5XlI'
            + self.serverExtension
            + self.clientExtension
            + str(self._key.public_key)
            + self._cookie
            + self._packed_nonce
            + self._box.encrypt(initiatePacket, self._full_nonce('I')).ciphertext)
        self.transport.write(packet, (self.host, self.port))
        self.awaiting = 'message'
        self.counter = 1
        self.reschedule()

        from twisted.internet import reactor
        for x in xrange(5):
            reactor.callLater(x * 10 + 1, self.write, ('%d\n' % (x,)) * 1028 + 'hi')

    def sendMessage(self, message):
        self.nextNonce()
        packet = (
            'QvnQ5XlM'
            + self.serverExtension
            + self.clientExtension
            + str(self._key.public_key)
            + self._packed_nonce
            + self._box.encrypt(message.pack(), self._full_nonce('M')).ciphertext)
        self.transport.write(packet, (self.host, self.port))
        self.sentMessageAt[message.id] = self.lastMessage = time.time()
        self._weAcked.update(message.ranges)

    def datagram_message(self, data):
        assert data[:8] == 'RL3aNMXM'
        assert data[8:24] == self.clientExtension
        assert data[24:40] == self.serverExtension
        now = time.time()
        nonce = 'CurveCP-server-M' + data[40:48]
        parsed = messageParser(self._box.decrypt(data[48:], nonce)).message()
        self.parseMessage(now, parsed)

    def parseMessage(self, now, message):
        if message.resolution:
            from twisted.internet import reactor
            reactor.stop()

        sentAt = self.sentMessageAt.pop(message.previousID, None)
        if sentAt is not None:
            self._processDelta(now, now - sentAt)
        print 'in', message
        if message.id:
            self.previousID = message.id
        self._theyAcked.update(message.ranges)
        newbuffer = []
        for dataRange, lowerBound, d, data in self.outbuffer:
            if dataRange & self._theyAcked:
                dataRange.difference_update(self._theyAcked)
                if not dataRange:
                    d.callback(time.time())
                    continue
            newbuffer.append((dataRange, lowerBound, d, data))
        self.outbuffer = newbuffer
        if not message.data:
            return
        i = halfOpen(message.dataPos, message.dataPos + len(message.data))
        new = IntervalSet([i]) - self._received
        if not new:
            return
        self._received.add(i)
        newData = message.data[new.lower_bound() - i.lower_bound:new.upper_bound() - i.upper_bound or None]
        self.fragment.add((i.lower_bound, newData))
        if len(self._received) > 1 or self._received.lower_bound() != 0:
            return
        newData = ''.join([d for _, d in self.fragment])
        self.fragment = sortedlist()
        print 'got', len(newData)

    def dataToSend(self):
        if not self.outbuffer:
            return 0, ''
        dataRange, lowerBound, _, data = self.outbuffer[0]
        dataPos = dataRange.lower_bound()
        return dataPos, data[dataPos - lowerBound:dataPos - lowerBound + 1024]

        toSend = self._sent - self._theyAcked
        for i in toSend:
            break
        else:
            return 0, ''
        data = self.data[i.lower_bound:min(i.upper_bound, i.lower_bound + 1024)]
        return i.lower_bound, data

    def sendAMessage(self):
        self.delayedCall = None
        self.reschedule()

        dataPos, data = self.dataToSend()
        if not data and self._received == self._weAcked:
            return
        print 'sent after %0.5fs' % (self.nextAction,)
        message = _Message(
            self.counter,
            self.previousID,
            list(self._received)[:6],
            None,
            dataPos,
            data,
        )
        print 'out', message
        self.counter += 1
        self.sendMessage(message)

    def _processDelta(self, now, rtt):
        print rtt,
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
        rttTimeout = self.rttAverage + 4 * self.rttDeviation
        rttTimeout += 8 * self.secPerMessage

        rttDelta = rtt - self.rttHighwater
        self.rttHighwater += rttDelta / 1024
        rttDelta = rtt - self.rttLowwater
        if rttDelta > 0:
            self.rttLowwater += rttDelta / 8192
        else:
            self.rttLowwater += rttDelta / 256

        print self.rttHighwater, self.rttLowwater, self.rttAverage, rttTimeout

        if now < self.rttLastSpeedAdjustment + 16 * self.secPerMessage:
            return

        if now - self.rttLastSpeedAdjustment > 10:
            self.secPerMessage = 1 + random() * .125
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
                self.secPerMessage += self.secPerMessage * random() * 0.25
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

    def reschedule(self):
        nextActionAt = time.time() + 1
        if self.lastMessage:
            nextActionAt = min(nextActionAt, self.lastMessage + self.secPerMessage)
        self.nextAction = nextAction = max(nextActionAt - time.time(), 0.0001)
        if self.delayedCall is not None:
            self.delayedCall.reset(nextAction)
        else:
            from twisted.internet import reactor
            self.delayedCall = reactor.callLater(nextAction, self.sendAMessage)

    def write(self, data):
        if not data:
            return defer.succeed(None)
        d = defer.Deferred()
        lowerBound = self._sent.upper_bound() if self._sent else 0
        dataRange = halfOpen(lowerBound, lowerBound + len(data))
        self.outbuffer.append((IntervalSet([dataRange]), lowerBound, d, data))
        self._sent.add(dataRange)
        return d

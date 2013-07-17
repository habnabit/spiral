from __future__ import division, absolute_import

import collections
import os
import struct
import time

from blist import sortedlist
from interval import IntervalSet
from nacl.public import PublicKey, PrivateKey, Box
from twisted.internet import defer, task
from twisted.internet.protocol import DatagramProtocol

from spiral.curvecp.pynacl.chicago import Chicago
from spiral.curvecp.pynacl.interval import halfOpen
from spiral.curvecp.pynacl.message import Message, messageParser
from spiral.entropy import random


QueuedMessage = collections.namedtuple('QueuedMessage', [
    'interval', 'lowerBound', 'deferred', 'sentAt', 'data',
])

def showMessage(tag, message, sentAt=None):
    print tag, message.id, IntervalSet(message.ranges),
    print halfOpen(message.dataPos, message.dataPos + len(message.data)),
    print len(message.data), sentAt and len(sentAt)

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
        self.chicago = Chicago()
        self.sentMessageAt = {}
        self.delayedCall = None
        self.looper = task.LoopingCall(self.showRanges)

    def showRanges(self):
        print 'received  ', self._received
        print 'we acked  ', self._weAcked
        print 'sent      ', self._sent
        print 'they acked', self._theyAcked

    def nextNonce(self):
        self._nonce = (self._nonce + 1) % (2 ** 64)

    @property
    def _packed_nonce(self):
        return struct.pack('!Q', self._nonce)

    def _full_nonce(self, which):
        return 'CurveCP-client-' + which + self._packed_nonce

    def startProtocol(self):
        self._nonce = random.randrange(2 ** 64)
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
        self.looper.start(10)

        from twisted.internet import reactor
        for x in xrange(500):
            reactor.callLater(x * 0.1 + 1, self.write, ('%d\n' % (x,)) * 1028 + 'hi')

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
        self.sentMessageAt[message.id] = self.chicago.lastMessage = time.time()
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
            self.chicago.processDelta(now, now - sentAt)
        showMessage('in', message)
        if message.id:
            self.previousID = message.id
        self._theyAcked.update(message.ranges)
        newbuffer = []
        for qm in self.outbuffer:
            if qm.interval & self._theyAcked:
                qm.interval.difference_update(self._theyAcked)
                if not qm.interval:
                    qm.deferred.callback(time.time())
                    continue
            newbuffer.append(qm)
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
        if message.id:
            self.sendAMessage(ackOnly=True)
        if len(self._received) > 1 or self._received.lower_bound() != 0:
            return
        newData = ''.join([d for _, d in self.fragment])
        self.fragment = sortedlist()

    def dataToSend(self, qm):
        dataPos = qm.interval.lower_bound()
        return dataPos, qm.data[dataPos - qm.lowerBound:dataPos - qm.lowerBound + 1024], qm.sentAt

    def sendAMessage(self, ackOnly=False):
        self.delayedCall = None
        self.reschedule()

        shouldAckData = self._received != self._weAcked

        shouldSendData = False
        if self.outbuffer and not ackOnly:
            for qm in self.outbuffer[:1]:
                shouldSendData = (
                    not qm.sentAt
                    or qm.sentAt[-1] + self.chicago.rttTimeout < time.time())
                if shouldSendData:
                    break
        if not (shouldAckData or shouldSendData):
            return

        if shouldSendData:
            dataPos, data, sentAt = self.dataToSend(qm)
            messageID = self.counter
            self.counter += 1
            if qm.sentAt:
                self.chicago.timedOut()
        else:
            dataPos, data, sentAt = 0, '', None
            messageID = 0
        message = Message(
            messageID,
            self.previousID,
            list(self._received)[:6],
            None,
            dataPos,
            data,
        )
        self.sendMessage(message)
        if sentAt is not None:
            sentAt.append(time.time())
        showMessage('out', message, sentAt)

    def reschedule(self):
        nextAction = self.nextAction = self.chicago.nextAction()
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
        self.outbuffer.append(QueuedMessage(
            IntervalSet([dataRange]), lowerBound, d, [], data))
        self._sent.add(dataRange)
        return d

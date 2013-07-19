from __future__ import division, absolute_import

import bisect
import collections
import os
import struct
import time

#from blist import sortedlist
from interval import IntervalSet
from nacl.public import PublicKey, PrivateKey, Box
from twisted.internet import defer, task
from twisted.internet.protocol import DatagramProtocol
from twisted.python.failure import Failure

import spiral.curvecp.errors as e
from spiral.curvecp.pynacl.chicago import Chicago
from spiral.curvecp.pynacl.interval import halfOpen
from spiral.curvecp.pynacl.message import Message, parseMessage


_QueuedDataBase = collections.namedtuple('_QueuedDataBase', [
    'interval', 'lowerBound', 'deferreds', 'sentAt', 'data',
])

class QueuedData(_QueuedDataBase):
    def nextTimeoutIn(self, now, chicago):
        if not self.sentAt:
            return chicago.rttTimeout
        return max(self.sentAt[-1] + chicago.rttTimeout, 0)

    def __hash__(self):
        return id(self)

    def dataToSend(self):
        dataPos = self.interval.lower_bound()
        return dataPos, self.data, self.sentAt


def showMessage(tag, message, sentAt=None):
    print tag, message.id, message.previousID, IntervalSet(message.ranges),
    print halfOpen(message.dataPos, message.dataPos + len(message.data)),
    print len(message.data), sentAt and len(sentAt)

class _CurveCPBaseTransport(DatagramProtocol):
    def __init__(self, reactor, protocol, serverKey):
        self.reactor = reactor
        self.protocol = protocol
        self.serverKey = serverKey
        self._received = IntervalSet()
        self._weAcked = IntervalSet()
        self._sent = IntervalSet()
        self._theyAcked = IntervalSet()
        self.outbuffer = []
        self.previousID = 0
        self.fragment = []
        self.chicago = Chicago()
        self.sentMessageAt = {}
        self.delayedCalls = {}
        self.messageQueue = []
        self.deferred = defer.Deferred()
        self.lastAck = 0
        self._nonce = 0
        self.datafile = open('data.csv', 'w')

    messageMap = {}
    def datagramReceived(self, data, host_port):
        handler = self.messageMap.get(data[:8])
        if not handler:
            return
        meth = getattr(self, 'datagram_' + handler)
        meth(data, host_port)

    _nonceInfix = ''
    def _encryptForNonce(self, which, box, data):
        packedNonce = struct.pack('<Q', self._nonce)
        self._nonce += 1
        nonce = 'CurveCP-%s-%s%s' % (self._nonceInfix, which, packedNonce)
        return packedNonce + box.encrypt(data, nonce).ciphertext

    def _serializeMessage(self, message):
        return ''

    def sendMessage(self, message):
        packet = self._serializeMessage(message)
        self.transport.write(packet, self.peerHost)
        self.sentMessageAt[message.id] = self.chicago.lastSentAt = time.time()
        self._weAcked.update(message.ranges)
        print 'out', message.id, message.previousID

    def parseMessage(self, now, message):
        if message.resolution:
            excType = e.CurveCPConnectionDone if message.resolution == 'success' else e.CurveCPConnectionFailed
            reason = Failure(excType())
            self.protocol.connectionLost(reason)
            return
        print 'in', message.id, message.previousID

        sentAt = self.sentMessageAt.pop(message.previousID, None)
        if sentAt is not None:
            self.chicago.processDelta(now, now - sentAt)
            self.chicago.writerow(now, self.datafile)
        if message.id:
            self.previousID = message.id
            self.enqueue()
        self._theyAcked.update(message.ranges)
        newbuffer = []
        for qd in self.outbuffer:
            if qd.interval & self._theyAcked:
                qd.interval.difference_update(self._theyAcked)
                if not qd.interval:
                    for d in qd.deferreds:
                        d.callback(now)
                    self.cancel(qd)
                    continue
            newbuffer.append(qd)
        self.outbuffer = newbuffer
        if not message.data:
            return
        i = halfOpen(message.dataPos, message.dataPos + len(message.data))
        new = IntervalSet([i]) - self._received
        if not new:
            return
        self._received.add(i)
        newData = message.data[new.lower_bound() - i.lower_bound:new.upper_bound() - i.upper_bound or None]
        bisect.insort(self.fragment, (i.lower_bound, newData))
        if len(self._received) > 1 or self._received.lower_bound() != 0:
            return
        newData = ''.join([d for _, d in self.fragment])
        self.protocol.dataReceived(newData)
        self.fragment = []

    def sendAMessage(self):
        now = time.time()
        nextActionIn = None
        if self.previousID:
            dataPos, data, sentAt = 0, '', None
            messageID, previousID = 0, self.previousID
            self.previousID = 0
        elif self.messageQueue:
            qd = self.messageQueue.pop(0)
            print 'queued', len(self.messageQueue)
            dataPos, data, sentAt = qd.dataToSend()
            messageID, previousID = self.counter, 0
            self.counter += 1
            now = time.time()
            if qd.sentAt:
                self.chicago.timedOut(now)
            qd.sentAt.append(now)
        elif self.lastAck < now + 5:
            dataPos, data, sentAt = 0, '', None
            messageID, previousID = self.counter, 0
            self.counter += 1
            self.lastAck = now
            nextActionIn = 10
        else:
            print "doing nothing, let's wait"
            return 60

        message = Message(
            messageID,
            previousID,
            list(self._received)[:6],
            None,
            dataPos,
            data,
        )
        self.sendMessage(message)
        return nextActionIn

    def reschedule(self, what, nextActionIn=None):
        now = time.time()
        if nextActionIn is None:
            if what == 'message':
                nextActionIn = self.chicago.nextMessageIn(now)
            else:
                nextActionIn = what.nextTimeoutIn(now, self.chicago)
        print 'queueing', what, nextActionIn
        delayedCall = self.delayedCalls.get(what)
        if delayedCall is not None and delayedCall.active():
            delayedCall.reset(nextActionIn)
        else:
            self.delayedCalls[what] = self.reactor.callLater(
                nextActionIn, self._scheduledAction, what)

    def cancel(self, what):
        delayedCall = self.delayedCalls.pop(what, None)
        if delayedCall is not None and delayedCall.active():
            delayedCall.cancel()

    def _scheduledAction(self, what):
        nextActionIn = None
        if what == 'message':
            nextActionIn = self.sendAMessage()
        else:
            self.messageQueue.append(what)
        self.reschedule(what, nextActionIn=nextActionIn)

    def enqueue(self, data=None):
        self.reschedule('message')
        if data is not None:
            self.messageQueue.append(data)

    def write(self, data):
        if not data:
            return defer.succeed(None)
        ds = [defer.Deferred()]
        while data:
            if self.outbuffer and len(self.outbuffer[-1].data) < 1024:
                lastQD = self.outbuffer.pop()
                data = lastQD.data + data
                ds.extend(lastQD.deferreds)
                lowerBound = lastQD.lowerBound
            else:
                lowerBound = self._sent.upper_bound() if self._sent else 0
            queueableData = data[:1024]
            dataRange = halfOpen(lowerBound, lowerBound + len(queueableData))
            qd = QueuedData(
                IntervalSet([dataRange]), lowerBound,
                ds if len(data) <= 1024 else [], [], queueableData)
            self.outbuffer.append(qd)
            self.enqueue(qd)
            self._sent.add(dataRange)
            data = data[1024:]
        return ds[0]

class CurveCPClientTransport(_CurveCPBaseTransport):
    def __init__(self, reactor, protocol, serverKey, host, port,
                 serverExtension, clientKey=None, clientExtension='\x00' * 16):
        _CurveCPBaseTransport.__init__(self, reactor, protocol, serverKey)
        self.peerHost = host, port
        self.serverExtension = serverExtension
        if clientKey is None:
            clientKey = PrivateKey.generate()
        self.clientKey = clientKey
        self.clientExtension = clientExtension

    messageMap = {
        'RL3aNMXK': 'cookie',
        'RL3aNMXM': 'message',
    }
    _nonceInfix = 'client'

    def _serializeMessage(self, message):
        return (
            'QvnQ5XlM'
            + self.serverExtension
            + self.clientExtension
            + str(self._clientShortKey.public_key)
            + self._encryptForNonce('M', self._shortShortBox, message.pack()))

    def startProtocol(self):
        self._clientShortKey = PrivateKey.generate()
        self._shortLongBox = Box(self._clientShortKey, self.serverKey)
        packet = (
            'QvnQ5XlH'
            + self.serverExtension
            + self.clientExtension
            + str(self._clientShortKey.public_key)
            + '\0' * 64
            + self._encryptForNonce('H', self._shortLongBox, '\0' * 64))
        self.transport.write(packet, self.peerHost)

    def datagram_cookie(self, data, host_port):
        assert len(data) == 200
        assert data[:8] == 'RL3aNMXK'
        assert data[8:24] == self.clientExtension
        assert data[24:40] == self.serverExtension
        packetNonce = data[40:56]
        data = self._shortLongBox.decrypt(data[56:200], 'CurveCPK' + packetNonce)
        self._serverShortKey = PublicKey(data[:32])
        self._shortShortBox = Box(self._clientShortKey, self._serverShortKey)
        self._cookie = data[32:144]
        message = '\0' * 192
        longLongNonce = os.urandom(16)
        longLongBox = Box(self.clientKey, self.serverKey)
        initiatePacket = (
            str(self.clientKey.public_key)
            + longLongNonce
            + longLongBox.encrypt(str(self._clientShortKey.public_key), 'CurveCPV' + longLongNonce).ciphertext
            + "\aexample\003com".ljust(256, '\x00')
            + message)
        packet = (
            'QvnQ5XlI'
            + self.serverExtension
            + self.clientExtension
            + str(self._clientShortKey.public_key)
            + self._cookie
            + self._encryptForNonce('I', self._shortShortBox, initiatePacket))
        self.transport.write(packet, self.peerHost)
        self.counter = 1
        self.reschedule('message')
        self.protocol.makeConnection(self)
        self.deferred.callback(self.protocol)

    def datagram_message(self, data, host_port):
        assert data[:8] == 'RL3aNMXM'
        assert data[8:24] == self.clientExtension
        assert data[24:40] == self.serverExtension
        now = time.time()
        nonce = data[40:48]
        parsed = parseMessage(self._shortShortBox.decrypt(data[48:], 'CurveCP-server-M' + nonce))
        self.parseMessage(now, parsed)

from __future__ import division, absolute_import

import bisect
import collections
import heapq
import os
import struct
import time

from interval import IntervalSet
from nacl.exceptions import CryptoError
from nacl.public import PublicKey, PrivateKey, Box
from twisted.internet import defer
from twisted.internet.protocol import DatagramProtocol
from twisted.python.failure import Failure

import spiral.curvecp.errors as e
from spiral.curvecp.address import CurveCPAddress
from spiral.curvecp.util import nameToDNS, dnsToName
from spiral.curvecp.pynacl.chicago import Chicago
from spiral.curvecp.pynacl.interval import halfOpen
from spiral.curvecp.pynacl.message import Message, parseMessage
from spiral.util import MultiTimeout


_nonceStruct = struct.Struct('<Q')
_helloStruct = struct.Struct('<8x16x16x32x64x8s80s')
_cookieStruct = struct.Struct('<8x16x16x16s144s')
_cookieInnerStruct = struct.Struct('<32s96s')
_initiateStruct = struct.Struct('<8x16x16x32x96s8s')
_initiateInnerStruct = struct.Struct('<32s16s48s256s')
_serverMessageStruct = struct.Struct('<8x16x16x8s')
_clientMessageStruct = struct.Struct('<8x16x16x32x8s')


_QueuedThingBase = collections.namedtuple('_QueuedThingBase', [
    'interval', 'lowerBound', 'deferreds', 'sentAt', 'messageIDs', 'data',
])

class QueuedData(_QueuedThingBase):
    def __hash__(self):
        return id(self)

    def fillInMessage(self, message):
        return message._replace(dataPos=self.lowerBound, data=self.data)

class QueuedResolution(_QueuedThingBase):
    def __hash__(self):
        return id(self)

    def fillInMessage(self, message):
        return message._replace(dataPos=self.lowerBound, resolution=self.data)


def showMessage(tag, message, sentAt=None):
    print tag, message.id, message.previousID, IntervalSet(message.ranges),
    print halfOpen(message.dataPos, message.dataPos + len(message.data)),
    print len(message.data), sentAt and len(sentAt)

class _CurveCPBaseTransport(DatagramProtocol):
    timeouts = 1, 1, 2, 3, 5, 8, 13
    now = staticmethod(time.time)
    generateKey = staticmethod(PrivateKey.generate)
    urandom = staticmethod(os.urandom)

    def __init__(self, clock, serverKey, factory):
        self.clock = clock
        self.serverKey = serverKey
        self.factory = factory
        self._received = IntervalSet()
        self._weAcked = IntervalSet()
        self._sent = IntervalSet()
        self._theyAcked = IntervalSet()
        self.sentMessages = set()
        self.previousID = 0
        self.fragment = []
        self.congestion = Chicago()
        self.sentMessageAt = {}
        self.delayedCalls = {}
        self.messageQueue = []
        self.enqueuedMessages = set()
        self.deferred = defer.Deferred()
        self._nonce = 0
        self._theirLastNonce = 0
        self.counter = 1
        self.ourStreamEnd = None
        self.theirStreamEnd = None
        self.reads = self.writes = None
        self.done = False
        self.outstandingMessages = 0

    def _timedOutHandshaking(self):
        self.deferred.errback(e.HandshakeTimeout())

    def _write(self, data):
        self.transport.write(data, self.peerHost)

    def _retrySendingForHandshake(self, data):
        mt = MultiTimeout(
            self.clock, self.timeouts, self._timedOutHandshaking, self._write, data)
        mt.reset()
        return mt

    messageMap = {}
    def datagramReceived(self, data, host_port):
        if self.done:
            return
        handler = self.messageMap.get(data[:8])
        if not handler:
            return
        meth = getattr(self, 'datagram_' + handler)
        meth(data, host_port)

    _nonceInfix = ''
    def _encryptForNonce(self, which, box, data):
        packedNonce = _nonceStruct.pack(self._nonce)
        self._nonce += 1
        nonce = 'CurveCP-%s-%s%s' % (self._nonceInfix, which, packedNonce)
        return packedNonce + box.encrypt(data, nonce).ciphertext

    def _verifyNonce(self, nonce):
        unpacked, = _nonceStruct.unpack(nonce)
        ret = unpacked >= self._theirLastNonce
        self._theirLastNonce = unpacked
        return ret

    def _serializeMessage(self, message):
        return ''

    def sendMessage(self, message):
        packet = self._serializeMessage(message)
        self._write(packet)
        if message.id:
            self.sentMessageAt[message.id] = self.congestion.lastSentAt = self.now()
        self._weAcked.update(message.ranges)

    def parseMessage(self, now, message):
        message = parseMessage(message)

        sentAt = self.sentMessageAt.pop(message.previousID, None)
        if sentAt is not None:
            self.congestion.processDelta(now, now - sentAt)
        if message.id:
            self.clock.callLater(0, self.sendAMessage, ack=message.id)
        self._theyAcked.update(message.ranges)

        for qd in list(self.sentMessages):
            if qd.interval & self._theyAcked:
                qd.interval.difference_update(self._theyAcked)
                if not qd.interval:
                    for d in qd.deferreds:
                        d.callback(now)
                    self.cancel(qd)
                    self.outstandingMessages -= 1
                    self.sentMessages.remove(qd)

        if message.resolution and self.theirStreamEnd is None:
            self.theirStreamEnd = message.dataPos
            self.theirResolution = message.resolution
            self._received.add(halfOpen(message.dataPos, message.dataPos + 1))
            self.reads = 'closing'
            self._checkTheirResolution()
            self.protocol.readConnectionLost()
            return
        elif not message.data:
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
        self._checkTheirResolution()

    def _checkTheirResolution(self):
        if self.theirStreamEnd is None:
            return
        if len(self._received) != 1:
            return
        self.reads = 'closed'
        self._checkBothResolutions()

    def _checkBothResolutions(self):
        if self.reads == self.writes == 'closed' and not self.done:
            self.protocol.connectionLost(Failure(e.resolution_map[self.theirResolution]))
            self.cancel('message')
            self.clock.callLater(sum(self.timeouts), self._completelyDone)

    def _completelyDone(self):
        self.done = True

    def sendAMessage(self, ack=None):
        now = self.now()
        nextActionIn = None
        message = Message(
            id=self.counter,
            previousID=0,
            ranges=list(self._received)[:6],
            resolution=None,
            dataPos=0,
            data='',
        )

        if ack is not None:
            message = message._replace(id=0, previousID=ack)
        elif self.messageQueue:
            _, _, qd = heapq.heappop(self.messageQueue)
            self.enqueuedMessages.remove(qd)
            message = qd.fillInMessage(message)
            self.counter += 1
            now = self.now()
            if qd.sentAt:
                self.congestion.timedOut(now)
                self.sentMessageAt.pop(qd.messageIDs[-1], None)
            elif self.congestion.window is not None and self.outstandingMessages > self.congestion.window:
                self.enqueue(1, qd)
                return
            else:
                self.outstandingMessages += 1
            qd.sentAt.append(now)
            qd.messageIDs.append(message.id)
            self.sentMessages.add(qd)
            self.reschedule(qd)
        else:
            return 60

        self.sendMessage(message)
        return nextActionIn

    def reschedule(self, what, nextActionIn=None):
        now = self.now()
        if nextActionIn is None:
            if what == 'message':
                nextActionIn = self.congestion.nextMessageIn(now)
            else:
                nextActionIn = self.congestion.nextTimeoutIn(now, what)
        delayedCall = self.delayedCalls.get(what)
        if delayedCall is not None and delayedCall.active():
            delayedCall.reset(nextActionIn)
        else:
            self.delayedCalls[what] = self.clock.callLater(
                nextActionIn, self._scheduledAction, what)

    def cancel(self, what):
        delayedCall = self.delayedCalls.pop(what, None)
        if delayedCall is not None and delayedCall.active():
            delayedCall.cancel()

    def _scheduledAction(self, what):
        nextActionIn = None
        if what == 'message':
            nextActionIn = self.sendAMessage()
            self.reschedule(what, nextActionIn=nextActionIn)
        else:
            self.sentMessages.remove(what)
            if what.interval:
                self.enqueue(0, what)

    def enqueue(self, priority, *data):
        self.reschedule('message')
        for datum in data:
            if datum not in self.enqueuedMessages and datum.interval:
                heapq.heappush(self.messageQueue, (priority, datum.lowerBound, datum))
                self.enqueuedMessages.add(datum)

    def write(self, data):
        if not data:
            return defer.succeed(None)
        elif self.writes in ('closing', 'closed'):
            return defer.fail(e.CurveCPConnectionDone(
                'attempted a write after closing writes'))

        d = defer.Deferred()
        qds = []
        lowerBound = self._sent.upper_bound() if self._sent else 0
        while data:
            ds = []
            queueableData = data[:1024]
            dataRange = halfOpen(lowerBound, lowerBound + len(queueableData))
            qd = QueuedData(
                IntervalSet([dataRange]), lowerBound, ds, [], [], queueableData)
            self._sent.add(dataRange)
            lowerBound += len(queueableData)
            data = data[1024:]
            qds.append(qd)
        ds.append(d)
        self.enqueue(1, *qds)
        return d

    def _peerEstablished(self):
        self.protocol = self.factory.buildProtocol(self.getPeer())
        self.protocol.makeConnection(self)
        self.deferred.callback(self.protocol)
        self.reads = 'open'
        self.writes = 'open'

    def _doneWritingAcked(self, when):
        self.writes = 'closed'
        self._checkBothResolutions()
        return when

    def loseConnection(self, success=True):
        d = defer.Deferred()
        d.addCallback(self._doneWritingAcked)
        streamEnd = self.ourStreamEnd = self._sent.upper_bound() if self._sent else 0
        resolution = self.ourResolution = 'success' if success else 'failure'
        interval = IntervalSet([halfOpen(streamEnd, streamEnd + 1)])
        self.enqueue(1, QueuedResolution(interval, streamEnd, [d], [], [], resolution))
        self.writes = 'closing'
        return d


class CurveCPClientTransport(_CurveCPBaseTransport):
    def __init__(self, clock, serverKey, factory, host, port,
                 serverExtension, clientKey=None, clientExtension='\x00' * 16):
        _CurveCPBaseTransport.__init__(self, clock, serverKey, factory)
        self.peerHost = host, port
        self.serverDomain = host
        self.serverExtension = serverExtension
        if clientKey is None:
            clientKey = self.generateKey()
        self.clientKey = clientKey
        self.clientExtension = clientExtension
        self.awaiting = 'cookie'

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
        self._clientShortKey = self.generateKey()
        self._shortLongBox = Box(self._clientShortKey, self.serverKey)
        packet = (
            'QvnQ5XlH'
            + self.serverExtension
            + self.clientExtension
            + str(self._clientShortKey.public_key)
            + '\0' * 64
            + self._encryptForNonce('H', self._shortLongBox, '\0' * 64))
        self.helloMultiCall = self._retrySendingForHandshake(packet)

    def _verifyPacketStart(self, data):
        return (data[8:24] == self.clientExtension
                and data[24:40] == self.serverExtension)

    def datagram_cookie(self, data, host_port):
        if len(data) != _cookieStruct.size or not self._verifyPacketStart(data):
            return
        nonce, encrypted = _cookieStruct.unpack(data)
        try:
            decrypted = self._shortLongBox.decrypt(encrypted, 'CurveCPK' + nonce)
        except CryptoError:
            return
        serverShortKeyString, cookie = _cookieInnerStruct.unpack(decrypted)
        serverShortKey = PublicKey(serverShortKeyString)
        if self.awaiting != 'cookie' and (cookie != self._cookie or serverShortKey != self._serverShortKey):
            return

        self.peerHost = host_port
        if self.awaiting == 'cookie':
            self._cookie = cookie
            self._serverShortKey = serverShortKey
            self._shortShortBox = Box(self._clientShortKey, self._serverShortKey)
            message = '\1\0\0\0\0\0\0\0' + '\0' * 184
            longLongNonce = self.urandom(16)
            longLongBox = Box(self.clientKey, self.serverKey)
            initiatePacketContent = (
                str(self.clientKey.public_key)
                + longLongNonce
                + longLongBox.encrypt(str(self._clientShortKey.public_key), 'CurveCPV' + longLongNonce).ciphertext
                + nameToDNS(self.serverDomain)
                + message)
            initiatePacket = (
                'QvnQ5XlI'
                + self.serverExtension
                + self.clientExtension
                + str(self._clientShortKey.public_key)
                + self._cookie
                + self._encryptForNonce('I', self._shortShortBox, initiatePacketContent))
            self.helloMultiCall.cancel()
            self.initiateMultiCall = self._retrySendingForHandshake(initiatePacket)
            self.awaiting = 'first-message'
        else:
            self.initiateMultiCall.reset()

    def datagram_message(self, data, host_port):
        if self.awaiting not in ('first-message', 'message'):
            return
        if not self._verifyPacketStart(data):
            return
        nonce, = _serverMessageStruct.unpack_from(data)
        try:
            decrypted = self._shortShortBox.decrypt(data[48:], 'CurveCP-server-M' + nonce)
        except CryptoError:
            return
        if not self._verifyNonce(nonce):
            return
        if self.awaiting == 'first-message':
            self.initiateMultiCall.cancel()
            del self.initiateMultiCall
            del self.helloMultiCall
            self.awaiting = 'message'
            self.reschedule('message')
            self._peerEstablished()
        self.parseMessage(self.now(), decrypted)

    def getHost(self):
        host = self.transport.getHost()
        return CurveCPAddress(
            self.clientExtension, self.serverExtension, self.serverDomain,
            self.clientKey.public_key, (host.host, host.port))

    def getPeer(self):
        return CurveCPAddress(
            self.clientExtension, self.serverExtension, self.serverDomain,
            self.serverKey, self.peerHost)


class CurveCPServerTransport(_CurveCPBaseTransport):
    def __init__(self, clock, serverKey, factory, clientID):
        _CurveCPBaseTransport.__init__(self, clock, serverKey, factory)
        self.serverExtension = clientID[:16]
        self.clientExtension = clientID[16:32]
        self.clientKey = None
        self._clientShortKey = PublicKey(clientID[32:64])
        self.cookiePacket = None
        self.awaiting = 'hello'

    messageMap = {
        'QvnQ5XlH': 'hello',
        'QvnQ5XlI': 'initiate',
        'QvnQ5XlM': 'message',
    }
    _nonceInfix = 'server'

    def startProtocol(self):
        self._serverShortKey = self.generateKey()
        self._longShortBox = Box(self.serverKey, self._clientShortKey)
        self._shortShortBox = Box(self._serverShortKey, self._clientShortKey)

    def _serializeMessage(self, message):
        return (
            'RL3aNMXM'
            + self.clientExtension
            + self.serverExtension
            + self._encryptForNonce('M', self._shortShortBox, message.pack()))

    def _verifyPacketStart(self, data):
        return (data[8:24] == self.serverExtension
                and data[24:40] == self.clientExtension
                and data[40:72] == str(self._clientShortKey))

    def datagram_hello(self, data, host_port):
        if self.awaiting not in ('hello', 'initiate'):
            return
        if len(data) != _helloStruct.size or not self._verifyPacketStart(data):
            return
        nonce, encrypted = _helloStruct.unpack(data)
        try:
            self._longShortBox.decrypt(encrypted, 'CurveCP-client-H' + nonce)
        except CryptoError:
            return
        self.peerHost = host_port
        if self.awaiting == 'hello':
            self.cookie = self.urandom(96)
            boxData = str(self._serverShortKey.public_key) + self.cookie
            cookieNonce = self.urandom(16)
            cookiePacket = (
                'RL3aNMXK'
                + self.clientExtension
                + self.serverExtension
                + cookieNonce
                + self._longShortBox.encrypt(boxData, 'CurveCPK' + cookieNonce).ciphertext)
            self.cookieMultiCall = self._retrySendingForHandshake(cookiePacket)
            self.awaiting = 'initiate'
        else:
            self.cookieMultiCall.reset()

    def datagram_initiate(self, data, host_port):
        if self.awaiting not in ('initiate', 'message'):
            return
        cookie, nonce = _initiateStruct.unpack_from(data)
        if cookie != self.cookie or not self._verifyPacketStart(data):
            return
        try:
            decrypted = self._shortShortBox.decrypt(data[176:], 'CurveCP-client-I' + nonce)
        except CryptoError:
            return
        clientKeyString, vouchNonce, encryptedVouch, serverDomain = _initiateInnerStruct.unpack_from(decrypted)
        clientKey = PublicKey(clientKeyString)
        longLongBox = Box(self.serverKey, clientKey)
        try:
            vouchKey = longLongBox.decrypt(encryptedVouch, 'CurveCPV' + vouchNonce)
        except CryptoError:
            return
        if vouchKey != str(self._clientShortKey):
            return
        if self.clientKey is None:
            self.clientKey = clientKey
            self.serverDomain = dnsToName(serverDomain)
            self.reschedule('message')
            self._peerEstablished()
        elif self.clientKey != clientKey:
            return
        self.peerHost = host_port
        message = decrypted[352:]
        self.parseMessage(self.now(), message)
        if self.awaiting == 'initiate':
            self.cookieMultiCall.cancel()
            del self.cookieMultiCall
            self.awaiting = 'message'

    def datagram_message(self, data, host_port):
        if not self._verifyPacketStart(data):
            return
        nonce, = _clientMessageStruct.unpack_from(data)
        try:
            decrypted = self._shortShortBox.decrypt(data[80:], 'CurveCP-client-M' + nonce)
        except CryptoError:
            return
        if not self._verifyNonce(nonce):
            return
        self.peerHost = host_port
        self.parseMessage(self.now(), decrypted)

    def getHost(self):
        host = self.transport.getHost()
        return CurveCPAddress(
            self.clientExtension, self.serverExtension, self.serverDomain,
            self.serverKey.public_key, (host.host, host.port))

    def getPeer(self):
        return CurveCPAddress(
            self.clientExtension, self.serverExtension, self.serverDomain,
            self.clientKey, self.peerHost)

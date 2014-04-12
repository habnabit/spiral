from __future__ import division, absolute_import

import bisect
import collections
import heapq
import struct

from interval import IntervalSet
from nacl.exceptions import CryptoError
from nacl.public import PublicKey, PrivateKey, Box
from twisted.internet import defer
from twisted.internet.protocol import DatagramProtocol
from twisted.python.failure import Failure

from spiral.curvecp import errors as e
from spiral.curvecp.address import CurveCPAddress
from spiral.curvecp.util import nameToDNS
from spiral.curvecp._pynacl.chicago import Chicago
from spiral.curvecp._pynacl.interval import halfOpen
from spiral.curvecp._pynacl.message import Message, parseMessage
from spiral.keys import EphemeralKey
from spiral.util import MultiTimeout


_nonceStruct = struct.Struct('<Q')
_cookieStruct = struct.Struct('<8x16x16x16s144s')
_cookieInnerStruct = struct.Struct('<32s96s')
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
    _generateKey = staticmethod(PrivateKey.generate)
    _generateKeydir = staticmethod(EphemeralKey)

    def __init__(self, clock, serverKey, factory):
        self._clock = clock
        self._serverKey = serverKey
        self._factory = factory
        self._received = IntervalSet()
        self._weAcked = IntervalSet()
        self._sent = IntervalSet()
        self._theyAcked = IntervalSet()
        self._sentMessages = set()
        self._previousID = 0
        self._fragment = []
        self._congestion = Chicago()
        self._sentMessageAt = {}
        self._delayedCalls = {}
        self._messageQueue = []
        self._enqueuedMessages = set()
        self._deferred = defer.Deferred()
        self._nonce = 0
        self._theirLastNonce = 0
        self._counter = 1
        self._ourStreamEnd = None
        self._theirStreamEnd = None
        self._reads = self._writes = None
        self._done = False
        self._outstandingMessages = 0
        self._onDone = []

    def _now(self):
        return self._clock.seconds()

    def _timedOutHandshaking(self):
        self._deferred.errback(e.HandshakeTimeout())

    def _write(self, data):
        self.transport.write(data, self._peerHost)

    def _retrySendingForHandshake(self, data):
        mt = MultiTimeout(
            self._clock, self.timeouts, self._timedOutHandshaking, self._write, data)
        mt.reset()
        return mt

    messageMap = {}
    def datagramReceived(self, data, host_port):
        if self._done:
            return
        handler = self._messageMap.get(data[:8])
        if not handler:
            return
        meth = getattr(self, '_datagram_' + handler)
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

    def _sendMessage(self, message):
        packet = self._serializeMessage(message)
        self._write(packet)
        if message.id:
            self._sentMessageAt[message.id] = self._congestion.lastSentAt = self._now()
        self._weAcked.update(message.ranges)

    def _parseMessage(self, now, message):
        message = parseMessage(message)

        sentAt = self._sentMessageAt.pop(message.previousID, None)
        if sentAt is not None:
            self._congestion.processDelta(now, now - sentAt)
        if message.id:
            self._clock.callLater(0, self._sendAMessage, ack=message.id)
        self._theyAcked.update(message.ranges)

        for qd in list(self._sentMessages):
            if qd.interval & self._theyAcked:
                qd.interval.difference_update(self._theyAcked)
                if not qd.interval:
                    for d in qd.deferreds:
                        d.callback(now)
                    self._cancel(qd)
                    self._outstandingMessages -= 1
                    self._sentMessages.remove(qd)

        if message.resolution and self._theirStreamEnd is None:
            self._theirStreamEnd = message.dataPos
            self._theirResolution = message.resolution
            self._received.add(halfOpen(message.dataPos, message.dataPos + 1))
            self._reads = 'closing'
            self._checkTheirResolution()
            return
        elif not message.data:
            return
        i = halfOpen(message.dataPos, message.dataPos + len(message.data))
        new = IntervalSet([i]) - self._received
        if not new:
            return
        self._received.add(i)
        newData = message.data[new.lower_bound() - i.lower_bound:new.upper_bound() - i.upper_bound or None]
        bisect.insort(self._fragment, (i.lower_bound, newData))
        if len(self._received) > 1 or self._received.lower_bound() != 0:
            return
        newData = ''.join([d for _, d in self._fragment])
        self._protocol.dataReceived(newData)
        self._fragment = []
        self._checkTheirResolution()

    def _checkTheirResolution(self):
        if self._theirStreamEnd is None:
            return
        if len(self._received) != 1 or self._received.lower_bound() != 0:
            return
        self._reads = 'closed'
        self._protocol.readConnectionLost()
        self._checkBothResolutions()

    def notifyFinish(self):
        if self._done:
            return defer.succeed(None)
        d = defer.Deferred()
        self._onDone.append(d)
        return d

    def _checkBothResolutions(self):
        if self._reads == self._writes == 'closed' and not self._done:
            self._protocol.connectionLost(Failure(e.resolution_map[self._theirResolution]()))
            self._cancel('message')
            deferreds, self._onDone = self._onDone, None
            for d in deferreds:
                d.callback(None)
            # this used to be done on a callLater, but I can't remember why
            self._done = True

    def _sendAMessage(self, ack=None):
        now = self._now()
        nextActionIn = None
        message = Message(
            id=self._counter,
            previousID=0,
            ranges=list(self._received)[:6],
            resolution=None,
            dataPos=0,
            data='',
        )

        if ack is not None:
            message = message._replace(id=0, previousID=ack)
        elif self._messageQueue:
            _, _, qd = heapq.heappop(self._messageQueue)
            self._enqueuedMessages.remove(qd)
            message = qd.fillInMessage(message)
            self._counter += 1
            if qd.sentAt:
                self._congestion.timedOut(now)
                self._sentMessageAt.pop(qd.messageIDs[-1], None)
            elif self._congestion.window is not None and self._outstandingMessages > self._congestion.window:
                self._enqueue(1, qd)
                return
            else:
                self._outstandingMessages += 1
            qd.sentAt.append(now)
            qd.messageIDs.append(message.id)
            self._sentMessages.add(qd)
            self._reschedule(qd)
        else:
            return 60

        self._sendMessage(message)
        return nextActionIn

    def _reschedule(self, what, nextActionIn=None):
        now = self._now()
        if nextActionIn is None:
            if what == 'message':
                nextActionIn = self._congestion.nextMessageIn(now)
            else:
                nextActionIn = self._congestion.nextTimeoutIn(now, what)
        delayedCall = self._delayedCalls.get(what)
        if delayedCall is not None and delayedCall.active():
            delayedCall.reset(nextActionIn)
        else:
            self._delayedCalls[what] = self._clock.callLater(
                nextActionIn, self._scheduledAction, what)

    def _cancel(self, what):
        delayedCall = self._delayedCalls.pop(what, None)
        if delayedCall is not None and delayedCall.active():
            delayedCall.cancel()

    def _scheduledAction(self, what):
        nextActionIn = None
        if what == 'message':
            nextActionIn = self._sendAMessage()
            self._reschedule(what, nextActionIn=nextActionIn)
        else:
            self._sentMessages.remove(what)
            if what.interval:
                self._enqueue(0, what)

    def _enqueue(self, priority, *data):
        self._reschedule('message')
        for datum in data:
            if datum not in self._enqueuedMessages and datum.interval:
                heapq.heappush(self._messageQueue, (priority, datum.lowerBound, datum))
                self._enqueuedMessages.add(datum)

    def write(self, data):
        if not data:
            return defer.succeed(None)
        elif self._writes in ('closing', 'closed'):
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
        self._enqueue(1, *qds)
        return d

    def _peerEstablished(self):
        self._protocol = self._factory.buildProtocol(self.getPeer())
        self._protocol.makeConnection(self)
        self._deferred.callback(self._protocol)
        self._reads = 'open'
        self._writes = 'open'

    def _doneWritingAcked(self, when):
        self._writes = 'closed'
        self._checkBothResolutions()
        return when

    def loseConnection(self, success=True):
        d = defer.Deferred()
        d.addCallback(self._doneWritingAcked)
        streamEnd = self._ourStreamEnd = self._sent.upper_bound() if self._sent else 0
        resolution = self._ourResolution = 'success' if success else 'failure'
        interval = IntervalSet([halfOpen(streamEnd, streamEnd + 1)])
        self._enqueue(1, QueuedResolution(interval, streamEnd, [d], [], [], resolution))
        self._writes = 'closing'
        return d


class CurveCPClientTransport(_CurveCPBaseTransport):
    def __init__(self, clock, serverKey, factory, host, port,
                 serverExtension, clientKey=None, clientExtension='\x00' * 16):
        _CurveCPBaseTransport.__init__(self, clock, serverKey, factory)
        self._peerHost = host, port
        self._serverDomain = host
        self._serverExtension = serverExtension
        if clientKey is None:
            clientKey = self._generateKeydir()
        self._clientKey = clientKey
        self._clientExtension = clientExtension
        self._awaiting = 'cookie'

    _messageMap = {
        'RL3aNMXK': 'cookie',
        'RL3aNMXM': 'message',
    }
    _nonceInfix = 'client'

    def _serializeMessage(self, message):
        return (
            'QvnQ5XlM'
            + self._serverExtension
            + self._clientExtension
            + str(self._clientShortKey.public_key)
            + self._encryptForNonce('M', self._shortShortBox, message.pack()))

    def startProtocol(self):
        self._clientShortKey = self._generateKey()
        self._shortLongBox = Box(self._clientShortKey, self._serverKey)
        packet = (
            'QvnQ5XlH'
            + self._serverExtension
            + self._clientExtension
            + str(self._clientShortKey.public_key)
            + '\0' * 64
            + self._encryptForNonce('H', self._shortLongBox, '\0' * 64))
        self._helloMultiCall = self._retrySendingForHandshake(packet)

    def _verifyPacketStart(self, data):
        return (data[8:24] == self._clientExtension
                and data[24:40] == self._serverExtension)

    def _datagram_cookie(self, data, host_port):
        if len(data) != _cookieStruct.size or not self._verifyPacketStart(data):
            return
        nonce, encrypted = _cookieStruct.unpack(data)
        try:
            decrypted = self._shortLongBox.decrypt(encrypted, 'CurveCPK' + nonce)
        except CryptoError:
            return
        serverShortKeyString, cookie = _cookieInnerStruct.unpack(decrypted)
        serverShortKey = PublicKey(serverShortKeyString)
        if self._awaiting != 'cookie' and (cookie != self._cookie or serverShortKey != self._serverShortKey):
            return

        self._peerHost = host_port
        if self._awaiting == 'cookie':
            self._cookie = cookie
            self._serverShortKey = serverShortKey
            self._shortShortBox = Box(self._clientShortKey, self._serverShortKey)
            message = '\1\0\0\0\0\0\0\0' + '\0' * 184
            longLongNonce = self._clientKey.nonce()
            longLongBox = Box(self._clientKey.key, self._serverKey)
            initiatePacketContent = (
                str(self._clientKey.key.public_key)
                + longLongNonce
                + longLongBox.encrypt(str(self._clientShortKey.public_key), 'CurveCPV' + longLongNonce).ciphertext
                + nameToDNS(self._serverDomain)
                + message)
            initiatePacket = (
                'QvnQ5XlI'
                + self._serverExtension
                + self._clientExtension
                + str(self._clientShortKey.public_key)
                + self._cookie
                + self._encryptForNonce('I', self._shortShortBox, initiatePacketContent))
            self._helloMultiCall.cancel()
            self._initiateMultiCall = self._retrySendingForHandshake(initiatePacket)
            self._awaiting = 'first-message'
        else:
            self._initiateMultiCall.reset()

    def _datagram_message(self, data, host_port):
        if self._awaiting not in ('first-message', 'message'):
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
        if self._awaiting == 'first-message':
            self._initiateMultiCall.cancel()
            del self._initiateMultiCall
            del self._helloMultiCall
            self._awaiting = 'message'
            self._reschedule('message')
            self._peerEstablished()
        self._parseMessage(self._now(), decrypted)

    def getHost(self):
        host = self.transport.getHost()
        return CurveCPAddress(
            self._clientExtension, self._serverExtension, self._serverDomain,
            self._clientKey.key.public_key, host.host, host.port)

    def getPeer(self):
        return CurveCPAddress(
            self._clientExtension, self._serverExtension, self._serverDomain,
            self._serverKey, *self._peerHost)


class CurveCPServerTransport(_CurveCPBaseTransport):
    def __init__(self, clock, serverKey, factory, clientID, clientPubkey,
                 peerHost, serverShortClientShort, serverDomain):
        _CurveCPBaseTransport.__init__(self, clock, serverKey, factory)
        self._serverExtension = clientID[:16]
        self._clientExtension = clientID[16:32]
        self._clientShortPubkey = PublicKey(clientID[32:64])
        self._clientPubkey = clientPubkey
        self._peerHost = peerHost
        self._serverShortClientShort = serverShortClientShort
        self._serverDomain = serverDomain

    _messageMap = {
        'QvnQ5XlM': 'message',
    }
    _nonceInfix = 'server'

    def startProtocol(self):
        self._reschedule('message')
        self._peerEstablished()

    def _serializeMessage(self, message):
        return (
            'RL3aNMXM'
            + self._clientExtension
            + self._serverExtension
            + self._encryptForNonce('M', self._serverShortClientShort, message.pack()))

    def _verifyPacketStart(self, data):
        return (data[8:24] == self._serverExtension
                and data[24:40] == self._clientExtension
                and data[40:72] == str(self._clientShortPubkey))

    def _datagram_message(self, data, host_port):
        if not self._verifyPacketStart(data):
            return
        nonce, = _clientMessageStruct.unpack_from(data)
        try:
            decrypted = self._serverShortClientShort.decrypt(data[80:], 'CurveCP-client-M' + nonce)
        except CryptoError:
            return
        if not self._verifyNonce(nonce):
            return
        self._peerHost = host_port
        self._parseMessage(self._now(), decrypted)

    def getHost(self):
        host = self.transport.getHost()
        return CurveCPAddress(
            self._clientExtension, self._serverExtension, self._serverDomain,
            self._serverKey.key.public_key, host.host, host.port)

    def getPeer(self):
        return CurveCPAddress(
            self._clientExtension, self._serverExtension, self._serverDomain,
            self._clientPubkey, *self._peerHost)

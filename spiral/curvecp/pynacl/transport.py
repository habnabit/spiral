from __future__ import division, absolute_import

import bisect
import collections
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


_nonceStruct = struct.Struct('<Q')
_helloStruct = struct.Struct('<8x16x16x32x64x8s80s')
_cookieStruct = struct.Struct('<8x16x16x16s144s')
_cookieInnerStruct = struct.Struct('<32s96s')
_initiateStruct = struct.Struct('<8x16x16x32x96s8s')
_initiateInnerStruct = struct.Struct('<32s16s48s256s')
_serverMessageStruct = struct.Struct('<8x16x16x8s')
_clientMessageStruct = struct.Struct('<8x16x16x32x8s')


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
    def __init__(self, reactor, serverKey, factory):
        self.reactor = reactor
        self.serverKey = serverKey
        self.factory = factory
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
        self._nonce = 0
        self._theirLastNonce = 0
        self.counter = 1
        self.ourStreamEnd = None
        self.theirStreamEnd = None
        self.doneSending = False
        self.doneReceiving = False
        self.datafile = open('data.%d.csv' % (os.getpid(),), 'w')

    messageMap = {}
    def datagramReceived(self, data, host_port):
        if self.doneSending and self.doneReceiving:
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
        self.transport.write(packet, self.peerHost)
        self.sentMessageAt[message.id] = self.chicago.lastSentAt = time.time()
        self._weAcked.update(message.ranges)
        print 'out', message.id, message.previousID

    def parseMessage(self, now, message):
        message = parseMessage(message)
        if message.resolution and self.theirStreamEnd is not None:
            self.theirStreamEnd = message.dataPos
            self.startedResolving = True
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
        dataPos, data, sentAt = 0, '', None
        messageID, previousID = self.counter, self.previousID
        resolution = None
        if self.previousID:
            messageID = 0
            self.previousID = 0
        elif self.messageQueue:
            qd = self.messageQueue.pop(0)
            print 'queued', len(self.messageQueue)
            dataPos, data, sentAt = qd.dataToSend()
            previousID = 0
            self.counter += 1
            now = time.time()
            if qd.sentAt:
                self.chicago.timedOut(now)
            qd.sentAt.append(now)
        elif self.ourStreamEnd is not None:
            dataPos = self.ourStreamEnd
            resolution = self.ourResolution
            self.counter += 1
        elif self.chicago.lastSentAt + 5 < now:
            self.counter += 1
            nextActionIn = 10
        else:
            print "doing nothing, let's wait"
            return 60

        message = Message(
            messageID,
            previousID,
            list(self._received)[:6],
            resolution,
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
        if self.ourStreamEnd is not None or not data:
            return defer.succeed(None)
        print 'writing', len(data),
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

    def _peerEstablished(self):
        self.protocol = self.factory.buildProtocol(self.getPeer())
        self.protocol.makeConnection(self)
        self.deferred.callback(self.protocol)

    def loseConnection(self, success=True):
        print 'ok bye'
        self.reschedule('message')
        self.ourStreamEnd = self._sent.upper_bound() if self._sent else 0
        self.ourResolution = 'success' if success else 'failure'


class CurveCPClientTransport(_CurveCPBaseTransport):
    def __init__(self, reactor, serverKey, factory, host, port,
                 serverExtension, clientKey=None, clientExtension='\x00' * 16):
        _CurveCPBaseTransport.__init__(self, reactor, serverKey, factory)
        self.peerHost = host, port
        self.serverDomain = host
        self.serverExtension = serverExtension
        if clientKey is None:
            clientKey = PrivateKey.generate()
        self.clientKey = clientKey
        self.clientExtension = clientExtension
        self._cookie = None

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

    def _verifyPacketStart(self, data):
        return (data[8:24] == self.clientExtension
                and data[24:40] == self.serverExtension)

    def datagram_cookie(self, data, host_port):
        if len(data) != _cookieStruct.size or not self._verifyPacketStart(data):
            print 'bad cookie'
            return
        nonce, encrypted = _cookieStruct.unpack(data)
        try:
            decrypted = self._shortLongBox.decrypt(encrypted, 'CurveCPK' + nonce)
        except CryptoError:
            print 'bad cookie crypto'
            return
        serverShortKeyString, cookie = _cookieInnerStruct.unpack(decrypted)
        serverShortKey = PublicKey(serverShortKeyString)
        if self._cookie is None:
            self._cookie = cookie
            self._serverShortKey = serverShortKey
            self._shortShortBox = Box(self._clientShortKey, self._serverShortKey)
            self.reschedule('message')
            self._peerEstablished()
            message = '\0' * 192
            longLongNonce = os.urandom(16)
            longLongBox = Box(self.clientKey, self.serverKey)
            initiatePacketContent = (
                str(self.clientKey.public_key)
                + longLongNonce
                + longLongBox.encrypt(str(self._clientShortKey.public_key), 'CurveCPV' + longLongNonce).ciphertext
                + nameToDNS(self.serverDomain)
                + message)
            self.initiatePacket = (
                'QvnQ5XlI'
                + self.serverExtension
                + self.clientExtension
                + str(self._clientShortKey.public_key)
                + self._cookie
                + self._encryptForNonce('I', self._shortShortBox, initiatePacketContent))
        elif cookie != self._cookie or serverShortKey != self._serverShortKey:
            print 'already got cookie'
            return
        self.peerHost = host_port
        self.transport.write(self.initiatePacket, self.peerHost)

    def datagram_message(self, data, host_port):
        if not self._verifyPacketStart(data):
            print 'bad message'
            return
        nonce, = _serverMessageStruct.unpack_from(data)
        try:
            decrypted = self._shortShortBox.decrypt(data[48:], 'CurveCP-server-M' + nonce)
        except CryptoError:
            print 'bad message crypto'
            return
        if not self._verifyNonce(nonce):
            print 'bad nonce'
            return
        self.parseMessage(time.time(), decrypted)

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
    def __init__(self, reactor, serverKey, factory, clientID):
        _CurveCPBaseTransport.__init__(self, reactor, serverKey, factory)
        self.serverExtension = clientID[:16]
        self.clientExtension = clientID[16:32]
        self.clientKey = None
        self._clientShortKey = PublicKey(clientID[32:64])
        self._serverShortKey = PrivateKey.generate()
        self._longShortBox = Box(self.serverKey, self._clientShortKey)
        self._shortShortBox = Box(self._serverShortKey, self._clientShortKey)
        self.cookiePacket = None

    messageMap = {
        'QvnQ5XlH': 'hello',
        'QvnQ5XlI': 'initiate',
        'QvnQ5XlM': 'message',
    }
    _nonceInfix = 'server'

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
        if len(data) != _helloStruct.size or not self._verifyPacketStart(data):
            print 'bad hello'
            return
        nonce, encrypted = _helloStruct.unpack(data)
        try:
            self._longShortBox.decrypt(encrypted, 'CurveCP-client-H' + nonce)
        except CryptoError:
            print 'bad hello crypto'
            return
        if self.cookiePacket is None:
            self.cookie = os.urandom(96)
            boxData = str(self._serverShortKey.public_key) + self.cookie
            cookieNonce = os.urandom(16)
            self.cookiePacket = (
                'RL3aNMXK'
                + self.serverExtension
                + self.clientExtension
                + cookieNonce
                + self._longShortBox.encrypt(boxData, 'CurveCPK' + cookieNonce).ciphertext)
        self.peerHost = host_port
        self.transport.write(self.cookiePacket, self.peerHost)

    def datagram_initiate(self, data, host_port):
        cookie, nonce = _initiateStruct.unpack_from(data)
        if cookie != self.cookie or not self._verifyPacketStart(data):
            print 'bad initiate'
            return
        try:
            decrypted = self._shortShortBox.decrypt(data[176:], 'CurveCP-client-I' + nonce)
        except CryptoError:
            print 'bad initiate crypto'
            return
        clientKeyString, vouchNonce, encryptedVouch, serverDomain = _initiateInnerStruct.unpack_from(decrypted)
        clientKey = PublicKey(clientKeyString)
        longLongBox = Box(self.serverKey, clientKey)
        try:
            vouchKey = longLongBox.decrypt(encryptedVouch, 'CurveCPV' + vouchNonce)
        except CryptoError:
            print 'bad vouch crypto'
            return
        if vouchKey != str(self._clientShortKey):
            print 'bad vouch'
            return
        if self.clientKey is None:
            self.clientKey = clientKey
            self.serverDomain = dnsToName(serverDomain)
            self.reschedule('message')
            self._peerEstablished()
            self.protocol.start(self.reactor, True)
        elif self.clientKey != clientKey:
            print 'already got key'
            return
        self.peerHost = host_port
        message = decrypted[352:]
        self.parseMessage(time.time(), message)

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
        self.parseMessage(time.time(), decrypted)

    def getHost(self):
        host = self.transport.getHost()
        return CurveCPAddress(
            self.clientExtension, self.serverExtension, self.serverDomain,
            self.serverKey.public_key, (host.host, host.port))

    def getPeer(self):
        return CurveCPAddress(
            self.clientExtension, self.serverExtension, self.serverDomain,
            self.clientKey, self.peerHost)

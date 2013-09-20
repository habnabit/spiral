import struct

from nacl.public import PrivateKey, Box
import pytest
from twisted.internet import defer
from twisted.internet.protocol import Factory
from twisted.internet.task import Clock
from twisted.test.proto_helpers import AccumulatingProtocol, FakeDatagramTransport

import spiral.curvecp.errors as e
from spiral.curvecp.pynacl import transport
from spiral.curvecp.pynacl.interval import halfOpen
from spiral.curvecp.pynacl.message import Message
from spiral.curvecp.pynacl.test.util import runUntilNext, nextCallIn


nonceStruct = struct.Struct('<Q')

clientLongKey = PrivateKey('67c08747363633d2e3f8c00e3d67822ece85714015131dac10e88ae09dab523e'.decode('hex'))
clientShortKey = PrivateKey('1057deeabc6fa4b9a255416915ce4a5f6bbe4255511541e1c390d217b970e0cb'.decode('hex'))
clientExtension = '\1' * 16
clientHostPort = '0.0.0.0', 1235
clientHostPort2 = '0.0.0.0', 21235

serverLongKey = PrivateKey('2de5f46cad518a4e84295f615cc35cb0fe83ba5339a5be611ddef17969e01d1c'.decode('hex'))
serverShortKey = PrivateKey('2f13e4722b9441b3111661c7f27f94a9fa4223e293bef5bad13846a3c6ad4f29'.decode('hex'))
serverExtension = '\2' * 16
serverHostPort = '0.0.0.0', 1234
serverHostPort2 = '0.0.0.0', 21234

clientServerShortBox = Box(clientShortKey, serverShortKey.public_key)
serverClientShortBox = Box(serverShortKey, clientShortKey.public_key)


def finishTransport(clock, t, key):
    t.generateKey = lambda: key
    t.now = clock.seconds
    t.urandom = lambda n: '\0' * n
    t.makeConnection(FakeDatagramTransport())
    return t

@pytest.fixture
def accumulatingFactory():
    fac = Factory()
    fac.protocol = AccumulatingProtocol
    fac.protocolConnectionMade = defer.Deferred()
    return fac

@pytest.fixture
def clientTransport(accumulatingFactory):
    clock = Clock()
    t = transport.CurveCPClientTransport(
        clock, serverLongKey.public_key, accumulatingFactory,
        '0.0.0.0', 1234, serverExtension, clientLongKey, clientExtension)
    return finishTransport(clock, t, clientShortKey)

@pytest.fixture
def serverTransport(accumulatingFactory):
    clock = Clock()
    t = transport.CurveCPServerTransport(
        clock, serverLongKey, accumulatingFactory,
        serverExtension + clientExtension + str(clientShortKey.public_key))
    return finishTransport(clock, t, serverShortKey)


clientHello = (
    'QvnQ5XlH'
    + serverExtension
    + clientExtension
    + str(clientShortKey.public_key)
    + '\0' * 64
    + '\0\0\0\0\0\0\0\0'
    + """
mB5gEyKKgwZRxdV1tcuPz4Ff1LfjBRPYFfWQKkD05cuCLQUudl6pwjfXQR0TinBP55+oLCF/7Nbu
mczV1H4fzQMKVsk8VEClTxAn3pmA7mI=""".decode('base64'))

def test_clientHello(clientTransport):
    t = clientTransport
    assert t.transport.written[0][0] == clientHello


serverCookie = (
    'RL3aNMXK'
    + clientExtension
    + serverExtension
    + '\0' * 16
    + """
3Om0Fyt0peSIM/hRfSi0lLHOcFX4Gz+zhLbJF3m+YqzAmCDWILiE9iMsyv20okKSYIjWwk+H4Hik
1xoH8Zlk69Qk5N3vgzJII1UKHzBgdVn4fQBaYqfn1EQ4SWUGFpd40Vxhbpa92pdBo7dnDYXysgV+
by16d6hOYXs4s1rIsnHleo9J030w5D0z4Nui/Wt7""".decode('base64'))

def test_serverCookie(serverTransport):
    t = serverTransport
    t.datagramReceived(clientHello, clientHostPort)
    assert t.transport.written[0][0] == serverCookie


clientInitiate = (
    'QvnQ5XlI'
    + serverExtension
    + clientExtension
    + str(clientShortKey.public_key)
    + '\0' * 96
    + '\1\0\0\0\0\0\0\0'
    + """
9WwqkgwaEt3i6R/X+7SK+NsfUWLlT5iOBoyRrhIfWOyGw90ZGaA6qNG7LKIJjCjhJNA8WcjrUESU
XM8hYnZ3mgH7NQCKKpgBJj8nXX5zgPaet4OyXU1f4tkexiBlnQsCDqmg3t6h8xpqeER5HVSeNvYE
g00hKXbw0Uh1SYmOvg7GPazk0d+4IRgSAT9qUcFC0bEuueD24RsFhm+MLmmVkJjpORTq6wLGjaey
B5TSI4uBFafXv01X6DTaSDHcuN0EkyMHYv3faxknYhhxof7fA6m5t6ARIOfr3foG0mZ629Cjb/XK
Qf7V6WJmReDAFoX5q0+rxClE4zM086KELEd/w8AFtHF6qgQrxxIJHyPwryICD358+UolGYP0bYbT
4D42hJ0JlTIa1h3wPLqQLyaRRTPDvHR38ENtMR/qWm6eg8/aK1x7WJPspl4vFJqthDwE9Vbmtixf
bgcieCxnVX47VkL37EntmzuSsdNhshiGkpLYJ4m8Tk9hVSlEy2N60ValKjZwOqthhUD/0jvoJSoz
Nhk4+Ki7496AAc71pZ8jA9Qd9Xggemlvedxf6EkTL7MyGnqmVwtz7iTnOyIYUNs0nA5KOdalwNSu
1NAtoIxx6YNEP7JebtO/nIvH+hN97/fYHJwU05wLtdXERwFVAvkRnpBlKj9QjaUIrg+70r1sPOUx
tkhIjjiBSbLTYrIBTwvFenlE5dGG9zVkXYXexKY+8Rcd2wG1m/X31fusjNxuXqY=
""".decode('base64'))

def test_clientInitiate(clientTransport):
    t = clientTransport
    t.datagramReceived(serverCookie, serverHostPort)
    assert t.transport.written[1][0] == clientInitiate


def test_handshakeTimeout_noResponse(clientTransport):
    t = clientTransport
    fired = []
    t.deferred.addErrback(fired.append)
    t.clock.pump([1, 1, 2, 3, 5, 8, 13])
    assert fired[0].check(e.HandshakeTimeout)

def test_handshakeTimeout_noResponseAfterCookie(clientTransport):
    t = clientTransport
    t.datagramReceived(serverCookie, serverHostPort)
    fired = []
    t.deferred.addErrback(fired.append)
    t.clock.pump([1, 1, 2, 3, 5, 8, 13])
    assert fired[0].check(e.HandshakeTimeout)

def test_handshakeTimeout_noResponseAfterHello(serverTransport):
    t = serverTransport
    t.datagramReceived(clientHello, clientHostPort)
    fired = []
    t.deferred.addErrback(fired.append)
    t.clock.pump([1, 1, 2, 3, 5, 8, 13])
    assert fired[0].check(e.HandshakeTimeout)


serverNullMessage = lambda nonce=1: (
    'RL3aNMXM'
    + clientExtension
    + serverExtension
    + nonceStruct.pack(nonce)
    + serverClientShortBox.encrypt(
        '\0' * 192, 'CurveCP-server-M' + nonceStruct.pack(nonce)).ciphertext)

clientNullMessage = lambda nonce=1: (
    'QvnQ5XlM'
    + serverExtension
    + clientExtension
    + str(clientShortKey.public_key)
    + nonceStruct.pack(nonce)
    + clientServerShortBox.encrypt(
        '\0' * 192, 'CurveCP-client-M' + nonceStruct.pack(nonce)).ciphertext)


class FakeCongestion(object):
    def __init__(self):
        self.rtts = []
        self.timeouts = []
        self.window = None
        self.lastSentAt = None
        self.secPerMessage = 1

    def writerow(self, now, fobj):
        pass

    def processDelta(self, now, rtt):
        self.rtts.append(rtt)

    def timedOut(self, now):
        self.timeouts.append(now)

    def nextMessageIn(self, now):
        return max((self.lastSentAt or now) + self.secPerMessage - now, 0)

    def nextTimeoutIn(self, now, qd):
        if not qd.sentAt:
            return self.secPerMessage * 10
        ret = now - qd.sentAt[-1] + self.secPerMessage * 10
        assert ret > 0
        return ret


def captureMessages(t):
    _sendMessage = t.sendMessage
    def capture(message):
        _sendMessage(message)
        capture.captured.append(message)
    capture.captured = []
    t.sendMessage = capture
    return t

@pytest.fixture
def clientMessageTransport(clientTransport):
    clientTransport.congestion = FakeCongestion()
    clientTransport.datagramReceived(serverCookie, serverHostPort)
    clientTransport.datagramReceived(serverNullMessage(), serverHostPort)
    return captureMessages(clientTransport)

@pytest.fixture
def serverMessageTransport(serverTransport):
    serverTransport.congestion = FakeCongestion()
    serverTransport.datagramReceived(clientHello, clientHostPort)
    serverTransport.datagramReceived(clientInitiate, clientHostPort)
    return captureMessages(serverTransport)

@pytest.fixture(scope='function', params=['client', 'server'])
def messageTransport(clientMessageTransport, serverMessageTransport, request):
    return clientMessageTransport if request.param == 'client' else serverMessageTransport


def test_ack(messageTransport):
    t = messageTransport
    t.parseMessage(t.now(), Message(1, 0, [], None, 0, 'hi').pack())
    runUntilNext(t.clock)
    assert t.sendMessage.captured[0] == Message(0, 1, [halfOpen(0, 2)], None, 0, '')

def test_sendingData(messageTransport):
    t = messageTransport
    t.write('hi')
    runUntilNext(t.clock)
    assert t.sendMessage.captured[0] == Message(1, 0, [], None, 0, 'hi')

def test_writeDeferredFires(messageTransport):
    t = messageTransport
    d = t.write('hi')
    fired = []
    d.addCallback(fired.append)
    assert not fired
    runUntilNext(t.clock)
    t.parseMessage(t.now(), Message(0, 1, [halfOpen(0, 2)], None, 0, '').pack())
    assert fired[0] == t.now()

def test_writeDeferredFiresSendingLotsOfData(messageTransport):
    t = messageTransport
    d = t.write('hi' * 1023)
    fired = []
    d.addCallback(fired.append)
    assert not fired
    t.clock.pump([1, 1])
    t.parseMessage(t.now(), Message(0, 1, [halfOpen(0, 2)], None, 0, '').pack())
    assert not fired
    t.parseMessage(t.now(), Message(0, 1, [halfOpen(0, 1024)], None, 0, '').pack())
    assert not fired
    t.parseMessage(t.now(), Message(0, 1, [halfOpen(0, 2045)], None, 0, '').pack())
    assert not fired
    t.parseMessage(t.now(), Message(0, 1, [halfOpen(0, 2046)], None, 0, '').pack())
    assert fired[0] == t.now()

def test_closeDeferredFires(messageTransport):
    t = messageTransport
    d = t.loseConnection()
    fired = []
    d.addCallback(fired.append)
    assert not fired
    t.clock.advance(1)
    t.parseMessage(t.now(), Message(0, 1, [halfOpen(0, 1)], None, 0, '').pack())
    assert fired[0] == t.now()

def test_closeDeferredFiresAfterSendingData(messageTransport):
    t = messageTransport
    t.write('hello')
    t.write('world')
    d = t.loseConnection()
    fired = []
    d.addCallback(fired.append)
    assert not fired
    t.clock.pump([1, 1, 1])
    t.parseMessage(t.now(), Message(0, 1, [halfOpen(0, 1)], None, 0, '').pack())
    assert not fired
    t.parseMessage(t.now(), Message(0, 1, [halfOpen(0, 6)], None, 0, '').pack())
    assert not fired
    t.parseMessage(t.now(), Message(0, 1, [halfOpen(0, 11)], None, 0, '').pack())
    assert fired[0] == t.now()

def test_receivingData(messageTransport):
    t = messageTransport
    t.parseMessage(t.now(), Message(1, 0, [], None, 0, 'hi').pack())
    assert t.protocol.data == 'hi'

def test_receivingFragmentedData(messageTransport):
    t = messageTransport
    t.parseMessage(t.now(), Message(3, 0, [], None, 6, '111').pack())
    assert t.protocol.data == ''
    t.parseMessage(t.now(), Message(2, 0, [], None, 3, '222').pack())
    assert t.protocol.data == ''
    t.parseMessage(t.now(), Message(1, 0, [], None, 0, '333').pack())
    assert t.protocol.data == '333222111'

def test_receivingOverlappingFragmentedData(messageTransport):
    t = messageTransport
    t.parseMessage(t.now(), Message(3, 0, [], None, 5, '2111').pack())
    assert t.protocol.data == ''
    t.parseMessage(t.now(), Message(2, 0, [], None, 2, '32221').pack())
    assert t.protocol.data == ''
    t.parseMessage(t.now(), Message(1, 0, [], None, 0, '3332').pack())
    assert t.protocol.data == '333222111'

def test_emptyMessageQueueWaitsForAWhile(messageTransport):
    t = messageTransport
    t.clock.advance(1)
    assert nextCallIn(t.clock) == 60

def test_emptyingTheMessageQueueWaitsForAWhile(messageTransport):
    t = messageTransport
    t.write('hi')
    t.clock.pump([1, 10])
    t.parseMessage(t.now(), Message(0, 1, [halfOpen(0, 2)], None, 0, '').pack())
    t.clock.advance(10)
    assert len(t.sendMessage.captured) == 2
    assert nextCallIn(t.clock) == 60

def test_messagesResendAfterTimingOut(messageTransport):
    t = messageTransport
    t.write('hi')
    t.clock.pump([1, 5, 5, 5, 5])
    assert len(t.sendMessage.captured) == 3

def test_messagesSendToLastHost(serverMessageTransport):
    t = serverMessageTransport
    t.datagramReceived(clientNullMessage(1), clientHostPort)
    t.write('hi')
    assert t.transport.written[0][1] == clientHostPort
    t.datagramReceived(clientNullMessage(2), clientHostPort2)
    t.clock.advance(1)
    assert t.transport.written[1][1] == clientHostPort2

def test_messagesSendToLastHostWithValidPackets(serverMessageTransport):
    t = serverMessageTransport
    t.datagramReceived(clientNullMessage(1), clientHostPort)
    t.write('hi')
    assert t.transport.written[0][1] == clientHostPort
    t.datagramReceived('hi', clientHostPort2)
    t.clock.advance(1)
    assert t.transport.written[1][1] == clientHostPort

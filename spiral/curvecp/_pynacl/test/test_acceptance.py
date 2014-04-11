import os
import pytest

from nacl.public import PublicKey
from twisted.internet.error import ProcessTerminated
from twisted.internet.utils import getProcessOutput
from twisted.internet import defer, protocol
from twisted.trial import unittest

from spiral.curvecp._pynacl import endpoints
from spiral.curvecp.errors import CurveCPConnectionDone
from spiral.keys import EphemeralKey
from spiral.test.util import BoringProcess


class DummyProtocol(protocol.Protocol):
    def __init__(self):
        self.accumulator = ''

    def connectionMade(self):
        self.transport.write(self.factory.message)

    def dataReceived(self, data):
        self.accumulator += data
        if self.accumulator == self.factory.message:
            self.transport.loseConnection()

    def readConnectionLost(self):
        pass

    def connectionLost(self, reason):
        self.factory.deferred.errback(reason)


class DummyFactory(protocol.Factory):
    def __init__(self, message):
        self.message = message
        self.deferred = defer.Deferred()

    protocol = DummyProtocol


class AcceptanceTests(unittest.TestCase):
    timeout = 5
    port = 28783

    @pytest.fixture(autouse=True)
    def init_tmpdir(self, tmpdir):
        self.tmpdir = tmpdir

    @defer.inlineCallbacks
    def test_client(self):
        from twisted.internet import reactor
        keydir = self.tmpdir.join('key').strpath
        yield getProcessOutput('curvecpmakekey', [keydir], env=os.environ)
        proc = BoringProcess()
        reactor.spawnProcess(
            proc, 'curvecpserver',
            ['curvecpserver', '127.0.0.1', keydir, '127.0.0.1', str(self.port), '0' * 32,
             'curvecpmessage', 'cat'],
            env=os.environ, childFDs={})
        self.addCleanup(proc.killMaybe)
        with open(os.path.join(keydir, 'publickey')) as infile:
            key = PublicKey(infile.read())
        endpoint = endpoints.CurveCPClientEndpoint(reactor, '127.0.0.1', self.port, key, '\x00' * 16)
        fac = DummyFactory('hello world')
        yield endpoint.connect(fac)
        yield self.assertFailure(fac.deferred, CurveCPConnectionDone)
        proc.transport.signalProcess('TERM')
        yield self.assertFailure(proc.deferred, ProcessTerminated)

    @defer.inlineCallbacks
    def test_server(self):
        from twisted.internet import reactor
        key = EphemeralKey()
        endpoint = endpoints.CurveCPServerEndpoint(reactor, 0, key)
        fac = DummyFactory('hello world')
        listeningPort = yield endpoint.listen(fac)
        self.addCleanup(listeningPort.stopListening)
        port = listeningPort.getHost().port
        yield getProcessOutput(
            'curvecpclient',
            ['127.0.0.1', str(key.key.public_key).encode('hex'), '127.0.0.1', str(port), '0' * 32,
             'curvecpmessage', '-c', 'socat', 'fd:6!!fd:7', 'system:"cat"'],
            env=os.environ, reactor=reactor)
        yield self.assertFailure(fac.deferred, CurveCPConnectionDone)

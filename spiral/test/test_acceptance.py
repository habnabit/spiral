import collections
import os
import pipes
import pytest

from twisted.internet.error import ProcessTerminated, ProcessDone
from twisted.internet.utils import getProcessOutput
from twisted.internet import defer
from twisted.trial import unittest

from spiral.test.util import BoringProcess


class RecorderProcess(BoringProcess):
    def __init__(self):
        BoringProcess.__init__(self)
        self.recorded = collections.defaultdict(str)

    def childDataReceived(self, fd, data):
        print fd, data
        self.recorded[fd] += data


def curvecpmServer(keydir, port, command):
    return ['curvecpmserver', keydir, str(port), '--', 'sh', '-c', command]


def curvecpServer(keydir, port, command):
    return ['curvecpserver', '127.0.0.1', keydir, '127.0.0.1', str(port), '0' * 32,
            'curvecpmessage', 'sh', '-c', command]


def curvecpmClient(key, port):
    return ['curvecpmclient', key, '127.0.0.1', port, 'socat', 'stdio', 'fd:6!!fd:7']


def curvecpClient(key, port):
    return ['curvecpclient', '127.0.0.1', key, '127.0.0.1', port, '0' * 32,
            'curvecpmessage', '-c', 'socat', 'stdio', 'fd:6!!fd:7']


servers = [curvecpmServer, curvecpServer]
clients = [curvecpmClient, curvecpClient]


def buildTest(target, clientArgFunc, serverArgFunc):
    @defer.inlineCallbacks
    def test_basic(self):
        serverOut = self.tmpdir.join('server-out')
        command = 'echo spam eggs; cat >' + pipes.quote(serverOut.strpath)
        serverProc = self.setUpServer(serverArgFunc, command)
        clientProc = self.setUpClient(clientArgFunc)

        clientProc.transport.writeToChild(0, 'eggs spam')
        clientProc.transport.closeStdin()
        yield self.assertFailure(clientProc.deferred, ProcessDone)
        serverProc.transport.signalProcess('TERM')
        yield self.assertFailure(serverProc.deferred, ProcessDone, ProcessTerminated)
        assert serverOut.read() == 'eggs spam'
        assert clientProc.recorded[1] == 'spam eggs\n'

    test_basic.__name__ = 'test_basic_%s_%s' % (clientArgFunc.__name__, serverArgFunc.__name__)
    target[test_basic.__name__] = test_basic


class AcceptanceTests(unittest.TestCase):
    timeout = 15
    port = 28783

    @pytest.fixture(autouse=True)
    def init_tmpdir(self, tmpdir):
        self.tmpdir = tmpdir

    @defer.inlineCallbacks
    def setUp(self):
        from twisted.internet import reactor
        self.reactor = reactor
        self.keydir = self.tmpdir.join('key').strpath
        yield getProcessOutput('curvecpmakekey', [self.keydir], env=os.environ)
        with open(os.path.join(self.keydir, 'publickey')) as infile:
            self.key = infile.read().encode('hex')

    def setUpServer(self, serverArgFunc, command):
        serverArgs = serverArgFunc(self.keydir, str(self.port), command)
        serverProc = RecorderProcess()
        self.reactor.spawnProcess(
            serverProc, serverArgs[0], serverArgs, env=os.environ, childFDs={2: 'r'})
        self.addCleanup(serverProc.killMaybe)
        return serverProc

    def setUpClient(self, clientArgFunc):
        clientArgs = clientArgFunc(self.key, str(self.port))
        clientProc = RecorderProcess()
        self.reactor.spawnProcess(
            clientProc, clientArgs[0], clientArgs, env=os.environ,
            childFDs={0: 'w', 1: 'r', 2: 2})
        self.addCleanup(clientProc.killMaybe)
        return clientProc

    for clientArgFunc in clients:
        for serverArgFunc in servers:
            buildTest(locals(), clientArgFunc, serverArgFunc)

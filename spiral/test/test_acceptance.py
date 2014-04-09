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
    def test(self):
        from twisted.internet import reactor
        keydir = self.tmpdir.join('key').strpath
        serverOut = self.tmpdir.join('server-out')
        yield getProcessOutput('curvecpmakekey', [keydir], env=os.environ)
        with open(os.path.join(keydir, 'publickey')) as infile:
            key = infile.read().encode('hex')

        command = 'echo spam eggs; cat >' + pipes.quote(serverOut.strpath)
        serverArgs = serverArgFunc(keydir, str(self.port), command)
        serverProc = RecorderProcess()
        reactor.spawnProcess(
            serverProc, serverArgs[0], serverArgs, env=os.environ, childFDs={2: 'r'})
        self.addCleanup(serverProc.killMaybe)

        clientArgs = clientArgFunc(key, str(self.port))
        clientProc = RecorderProcess()
        reactor.spawnProcess(
            clientProc, clientArgs[0], clientArgs, env=os.environ,
            childFDs={0: 'w', 1: 'r', 2: 2})
        self.addCleanup(clientProc.killMaybe)

        clientProc.transport.writeToChild(0, 'eggs spam')
        clientProc.transport.closeStdin()
        yield self.assertFailure(clientProc.deferred, ProcessDone)
        serverProc.transport.signalProcess('TERM')
        yield self.assertFailure(serverProc.deferred, ProcessDone, ProcessTerminated)
        assert serverOut.read() == 'eggs spam'
        assert clientProc.recorded[1] == 'spam eggs\n'

    test.__name__ = 'test_%s_%s' % (clientArgFunc.__name__, serverArgFunc.__name__)
    target[test.__name__] = test


class AcceptanceTests(unittest.TestCase):
    timeout = 15
    port = 28783

    @pytest.fixture(autouse=True)
    def init_tmpdir(self, tmpdir):
        self.tmpdir = tmpdir

    for clientArgFunc in clients:
        for serverArgFunc in servers:
            buildTest(locals(), clientArgFunc, serverArgFunc)

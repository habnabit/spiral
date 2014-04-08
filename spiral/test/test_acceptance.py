import collections
import os
import pipes
import pytest

from nacl.public import PublicKey
from twisted.internet.error import ProcessTerminated, ProcessDone
from twisted.internet.utils import getProcessOutput
from twisted.internet import defer, protocol
from twisted.trial import unittest

from spiral.curvecp._pynacl import endpoints
from spiral.curvecp.errors import CurveCPConnectionDone
from spiral.curvecp.keydir import EphemeralKey
from spiral.test.util import BoringProcess


class RecorderProcess(BoringProcess):
    def __init__(self):
        BoringProcess.__init__(self)
        self.recorded = collections.defaultdict(str)

    def childDataReceived(self, fd, data):
        print fd, data
        self.recorded[fd] += data


def buildTest(target, client, server):
    @defer.inlineCallbacks
    def test(self):
        from twisted.internet import reactor
        keydir = self.tmpdir.join('key').strpath
        serverOut = self.tmpdir.join('server-out')
        yield getProcessOutput('curvecpmakekey', [keydir], env=os.environ)
        with open(os.path.join(keydir, 'publickey')) as infile:
            key = infile.read().encode('hex')

        command = 'echo spam eggs; cat >' + pipes.quote(serverOut.strpath)
        if server == 'curvecpm':
            args = ['curvecpmserver', keydir, str(self.port), '--', 'sh', '-c', command]
        elif server == 'curvecp':
            args = ['curvecpserver', '127.0.0.1', keydir, '127.0.0.1', str(self.port), '0' * 32,
                    'curvecpmessage', 'sh', '-c', command]
        serverProc = RecorderProcess()
        reactor.spawnProcess(
            serverProc, args[0], args, env=os.environ, childFDs={2: 'r'})
        self.addCleanup(serverProc.killMaybe)

        if client == 'curvecpm':
            args = ['curvecpmclient', key, '127.0.0.1', str(self.port), 'socat', 'stdio', 'fd:6!!fd:7']
        elif client == 'curvecp':
            args = ['curvecpclient', '127.0.0.1', key, '127.0.0.1', str(self.port), '0' * 32,
                    'curvecpmessage', '-c', 'socat', 'stdio', 'fd:6!!fd:7']
        clientProc = RecorderProcess()
        reactor.spawnProcess(
            clientProc, args[0], args, env=os.environ,
            childFDs={0: 'w', 1: 'r', 2: 2})
        self.addCleanup(clientProc.killMaybe)

        clientProc.transport.writeToChild(0, 'eggs spam')
        clientProc.transport.closeStdin()
        yield self.assertFailure(clientProc.deferred, ProcessDone)
        serverProc.transport.signalProcess('TERM')
        yield self.assertFailure(serverProc.deferred, ProcessDone, ProcessTerminated)
        assert serverOut.read() == 'eggs spam'
        assert clientProc.recorded[1] == 'spam eggs\n'

    test.__name__ = 'test_client_%s_server_%s' % (client, server)
    target[test.__name__] = test


class AcceptanceTests(unittest.TestCase):
    timeout = 5
    port = 28783

    @pytest.fixture(autouse=True)
    def init_tmpdir(self, tmpdir):
        self.tmpdir = tmpdir

    for client in ['curvecp', 'curvecpm']:
        for server in ['curvecp', 'curvecpm']:
            if client == server == 'curvecp':
                continue
            buildTest(locals(), client, server)

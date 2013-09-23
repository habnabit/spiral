import argparse
import os

from twisted.internet.task import react
from twisted.internet import defer, protocol

from spiral.curvecp.pynacl.endpoints import CurveCPServerEndpoint
from spiral.curvecp.util import loadKeydir


class CurveCPMServerProcessProtocol(protocol.ProcessProtocol):
    def __init__(self, proto):
        self.proto = proto

    def childDataReceived(self, fd, data):
        assert fd == 1
        self.proto.transport.write(data)

    def childConnectionLost(self, fd):
        if fd == 1:
            self.proto.transport.loseConnection()


class CurveCPMServerProtocol(protocol.Protocol):
    def __init__(self):
        self.processProto = CurveCPMServerProcessProtocol(self)

    def connectionMade(self):
        print 'spawning'
        env = os.environ.copy()
        env.update(self.transport.getHost().asUCSPIEnv('server', 'server'))
        env.update(self.transport.getPeer().asUCSPIEnv('server', 'client'))
        self.factory.reactor.spawnProcess(
            self.processProto, self.factory.args.program,
            args=[self.factory.args.program] + self.factory.args.argv,
            env=env, childFDs={0: 'w', 1: 'r', 2: 2})

    def dataReceived(self, data):
        self.processProto.transport.writeToChild(0, data)

    def readConnectionLost(self):
        self.processProto.transport.closeChildFD(0)


class CurveCPMServerFactory(protocol.Factory):
    def __init__(self, reactor, args):
        self.reactor = reactor
        self.args = args

    protocol = CurveCPMServerProtocol


def twistedMain(reactor, args):
    fac = CurveCPMServerFactory(reactor, args)
    e = CurveCPServerEndpoint(reactor, loadKeydir(args.keydir), args.port)
    e.listen(fac)
    return defer.Deferred()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-n', '--name')
    parser.add_argument('-e', '--server-extension', default='0' * 32)
    parser.add_argument('keydir')
    parser.add_argument('port', type=int)
    parser.add_argument('program')
    parser.add_argument('argv', nargs='*')

    react(twistedMain, [parser.parse_args()])

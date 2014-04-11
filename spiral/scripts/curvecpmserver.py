import argparse
import os

from twisted.internet.task import react
from twisted.internet import defer, protocol
from twisted.python import log

from spiral.curvecp import CurveCPServerEndpoint, _curvecpm
from spiral.keys import Keydir


class CurveCPMServerProcessProtocol(protocol.ProcessProtocol):
    def __init__(self, proto):
        self.proto = proto

    def childDataReceived(self, fd, data):
        assert fd == 1
        self.proto.transport.write(data).addErrback(log.err, 'error writing data')

    def childConnectionLost(self, fd):
        if fd == 1:
            self.proto.transport.loseConnection().addErrback(log.err, 'error closing connection')


class CurveCPMServerProtocol(protocol.Protocol):
    def __init__(self):
        self.processProto = CurveCPMServerProcessProtocol(self)

    def connectionMade(self):
        args = [self.factory.args.program] + self.factory.args.argv
        log.msg('spawning %r' % args, category='success')
        env = os.environ.copy()
        env.update(self.transport.getHost().asUCSPIEnv('server', 'server'))
        env.update(self.transport.getPeer().asUCSPIEnv('server', 'client'))
        self.factory.reactor.spawnProcess(
            self.processProto, self.factory.args.program, args=args,
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
    _curvecpm.startLogging(args.verbosity)
    fac = CurveCPMServerFactory(reactor, args)
    e = CurveCPServerEndpoint(reactor, args.port, args.keydir)
    e.listen(fac)
    return defer.Deferred()

def main():
    parser = argparse.ArgumentParser()
    _curvecpm.addLogArguments(parser)
    parser.add_argument('-n', '--name')
    parser.add_argument('-e', '--server-extension', default='0' * 32)
    parser.add_argument('keydir', type=Keydir)
    parser.add_argument('port', type=int)
    parser.add_argument('program')
    parser.add_argument('argv', nargs='*')

    react(twistedMain, [parser.parse_args()])

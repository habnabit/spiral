from twisted.internet import defer

from nacl.public import PrivateKey

from spiral.curvecp.pynacl.server import CurveCPServerDispatcher
from spiral.curvecp.pynacl.transport import CurveCPClientTransport


class CurveCPClientEndpoint(object):
    def __init__(self, reactor, host, port, serverKey, serverExtension, clientKey=None,
                 clientExtension='\x00' * 16):
        self.reactor = reactor
        self.host = host
        self.port = port
        self.serverKey = serverKey
        self.serverExtension = serverExtension
        if clientKey is None:
            clientKey = PrivateKey.generate()
        self.clientKey = clientKey
        self.clientExtension = clientExtension

    def connect(self, fac):
        transport = CurveCPClientTransport(
            self.reactor, self.serverKey, fac, self.host, self.port,
            self.serverExtension, self.clientKey, self.clientExtension)
        self.reactor.listenUDP(0, transport)
        return transport.deferred


class CurveCPServerEndpoint(object):
    def __init__(self, reactor, serverKey, port):
        self.reactor = reactor
        self.serverKey = serverKey
        self.port = port

    def listen(self, fac):
        dispatcher = CurveCPServerDispatcher(self.reactor, self.serverKey, fac)
        return defer.succeed(self.reactor.listenUDP(self.port, dispatcher))

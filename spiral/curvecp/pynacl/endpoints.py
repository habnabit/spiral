from nacl.public import PrivateKey

from spiral.curvecp.pynacl.transport import CurveCPTransport


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
        proto = fac.buildProtocol(None)
        transport = CurveCPTransport(self.reactor, proto, self.host, self.port, self.serverKey, self.serverExtension,
                                     self.clientKey, self.clientExtension)
        self.reactor.listenUDP(0, transport)
        return transport.deferred

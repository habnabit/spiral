from twisted.internet.protocol import DatagramProtocol

from spiral.curvecp.pynacl.transport import CurveCPServerTransport


class CurveCPServerDispatcher(DatagramProtocol):
    def __init__(self, reactor, serverKey, factory):
        self.reactor = reactor
        self.serverKey = serverKey
        self.factory = factory
        self.transports = {}

    def datagramReceived(self, data, host_port):
        clientID = data[8:72]
        if clientID not in self.transports:
            if data[:8] != 'QvnQ5XlH':
                return
            print 'new transport', clientID.encode('hex')
            transport = self.transports[clientID] = CurveCPServerTransport(
                self.reactor, self.serverKey, self.factory, clientID)
            transport.transport = self.transport
            transport.startProtocol()
            transport.deferred.addErrback(self._transportFailed, clientID)

        self.transports[clientID].datagramReceived(data, host_port)

    def _transportFailed(self, reason, clientID):
        del self.transports[clientID]

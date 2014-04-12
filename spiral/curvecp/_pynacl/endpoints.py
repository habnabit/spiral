from twisted.internet import defer, interfaces
from zope.interface import implementer

from spiral.curvecp._pynacl.server import CurveCPServerDispatcher
from spiral.curvecp._pynacl.transport import CurveCPClientTransport


@implementer(interfaces.IStreamClientEndpoint)
class CurveCPClientEndpoint(object):
    """
    An `IStreamClientEndpoint`_ implementer for CurveCP clients.

    :param reactor: An `IReactorUDP`_ and `IReactorTime`_ provider.
    :param host: A hostname to connect to.
    :param port: The port to connect to the *host* on.
    :param serverKey: The server's public key, as a 32-byte string.
    :param serverExtension: Optionally, the 16-byte server extension. Defaults
        to all null bytes.
    :param clientKey: Optionally, an |IKeyAndNonceScheme| provider for the
        client's private key. Defaults to generating an ephemeral key for
        client the on every new connection.
    :param clientExtension: Optionally, the 16-byte client extension. Defaults
        to all null bytes.

    .. _IStreamClientEndpoint: http://twistedmatrix.com/documents/current/api/twisted.internet.interfaces.IStreamClientEndpoint.html
    .. _IReactorUDP: http://twistedmatrix.com/documents/current/api/twisted.internet.interfaces.IReactorUDP.html
    .. _IReactorTime: http://twistedmatrix.com/documents/current/api/twisted.internet.interfaces.IReactorTime.html
    """

    def __init__(self, reactor, host, port, serverKey, serverExtension='\x00' * 16,
                 clientKey=None, clientExtension='\x00' * 16):
        self.reactor = reactor
        self.host = host
        self.port = port
        self.serverKey = serverKey
        self.serverExtension = serverExtension
        self.clientKey = clientKey
        self.clientExtension = clientExtension

    def connect(self, fac):
        """
        Connect to a CurveCP host.

        :param fac: An `IProtocolFactory`_ provider whose ``buildProtocol``
            returns an `IHalfCloseableProtocol`_ provider.

        .. _IProtocolFactory: http://twistedmatrix.com/documents/current/api/twisted.internet.interfaces.IProtocolFactory.html
        .. _IHalfCloseableProtocol: http://twistedmatrix.com/documents/current/api/twisted.internet.interfaces.IHalfCloseableProtocol.html
        """
        transport = CurveCPClientTransport(
            self.reactor, self.serverKey, fac, self.host, self.port,
            self.serverExtension, self.clientKey, self.clientExtension)
        listeningPort = self.reactor.listenUDP(0, transport)
        transport.notifyFinish().addCallback(self._clientFinished, listeningPort)
        return transport._deferred

    def _clientFinished(self, ign, listeningPort):
        listeningPort.stopListening()


@implementer(interfaces.IStreamServerEndpoint)
class CurveCPServerEndpoint(object):
    """
    An `IStreamServerEndpoint`_ implementer for CurveCP servers.

    All incoming connections are accepted; for filtering based on client/server
    extension or server DNS name, please override ``buildProtocol`` to make
    decisions about the |ICurveCPAddress| provider passed to it.

    :param reactor: An `IReactorUDP`_ and `IReactorTime`_ provider.
    :param port: The port to listen on.
    :param serverKey: An |IKeyAndNonceScheme| provider representing the
        server's private key.

    .. _IStreamServerEndpoint: http://twistedmatrix.com/documents/current/api/twisted.internet.interfaces.IStreamServerEndpoint.html
    .. _IReactorUDP: http://twistedmatrix.com/documents/current/api/twisted.internet.interfaces.IReactorUDP.html
    .. _IReactorTime: http://twistedmatrix.com/documents/current/api/twisted.internet.interfaces.IReactorTime.html
    """

    def __init__(self, reactor, port, serverKey):
        self.reactor = reactor
        self.port = port
        self.serverKey = serverKey

    def listen(self, fac):
        """
        Listen for incoming CurveCP connections.

        :param fac: An `IProtocolFactory`_ provider whose ``buildProtocol``
            returns an `IHalfCloseableProtocol`_ provider.

        .. _IProtocolFactory: http://twistedmatrix.com/documents/current/api/twisted.internet.interfaces.IProtocolFactory.html
        .. _IHalfCloseableProtocol: http://twistedmatrix.com/documents/current/api/twisted.internet.interfaces.IHalfCloseableProtocol.html
        """
        dispatcher = CurveCPServerDispatcher(self.reactor, self.serverKey, fac)
        return defer.succeed(self.reactor.listenUDP(self.port, dispatcher))

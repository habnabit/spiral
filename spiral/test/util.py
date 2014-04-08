from twisted.internet import defer, protocol


class BoringProcess(protocol.ProcessProtocol):
    def __init__(self):
        self.deferred = defer.Deferred()

    def processEnded(self, reason):
        self.deferred.errback(reason)

    def killMaybe(self):
        if self.transport.pid is not None:
            self.transport.signalProcess('KILL')

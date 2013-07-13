import sys

from twisted.internet.base import ThreadedResolver
from twisted.internet.defer import Deferred
from twisted.internet.task import react
from twisted.names import dns, hosts, server
from twisted.names.root import bootstrap
from twisted.names.cache import CacheResolver
from twisted.python import log

from spiral import DNSCurveRecursiveResolver


def main(reactor):
    log.startLogging(sys.stdout)
    resolver = bootstrap(ThreadedResolver(reactor))
    d = Deferred()
    resolver.waiting.append(d)
    @d.addCallback
    def _resolverDone(resolver):
        resolver.__class__ = DNSCurveRecursiveResolver
        ca = [CacheResolver()]
        cl = [
            hosts.Resolver(file='/etc/hosts'),
            resolver,
        ]
        fac = server.DNSServerFactory([], ca, cl, False)
        fac.noisy = False
        p = dns.DNSDatagramProtocol(fac)
        reactor.listenUDP(2053, p)
        return Deferred()
    return d

react(main, [])

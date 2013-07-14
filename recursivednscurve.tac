import sys
import re

from twisted.application import service, internet
from twisted.internet.base import ThreadedResolver
from twisted.internet.defer import Deferred
from twisted.internet import reactor
from twisted.names.root import bootstrap
from twisted.names.cache import CacheResolver
from twisted.names import dns, hosts, server
from twisted.python import log

from spiral import DNSCurveRecursiveResolver


def makeService():
    resolver = bootstrap(ThreadedResolver(reactor))
    d = Deferred()
    resolver.waiting.append(d)
    @d.addCallback
    def _resolverDone(resolver):
        resolver.__class__ = DNSCurveRecursiveResolver

    ca = [CacheResolver(verbose=2)]
    cl = [
        hosts.Resolver(file='/etc/hosts'),
        resolver,
    ]

    f = server.DNSServerFactory([], ca, cl, verbose=False)
    f.noisy = False
    p = dns.DNSDatagramProtocol(f)
    ret = service.MultiService()
    for (klass, arg) in [(internet.TCPServer, f), (internet.UDPServer, p)]:
        s = klass(5053, arg)
        s.setServiceParent(ret)
    return ret


application = service.Application('spiral')
makeService().setServiceParent(application)

logfile = log.FileLogObserver(sys.__stdout__)
logfile.timeFormat = '-'
ignoredRegexp = re.compile('starting on|(?:Starting|Stopping) protocol|UDP Port \d+ Closed')
def filterFunc(event):
    if ignoredRegexp.search(event['message'][0]):
        return
    logfile.emit(event)
application.setComponent(log.ILogObserver, filterFunc)

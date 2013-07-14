import sys
import re

from twisted.application import service, internet
from twisted.internet import defer, reactor
from twisted.names.root import DeferredResolver
from twisted.names.cache import CacheResolver
from twisted.names import dns, hosts, server
from twisted.python import log

from spiral import DNSCurveRecursiveResolver, DNSCurveResolver


def bootstrap(resolver):
    domains = [chr(ord('a') + i) for i in range(13)]
    L = [resolver.lookupAddress('%s.root-servers.net' % d) for d in domains]
    d = defer.DeferredList(L)
    @d.addCallback
    def cb(results):
        hints = []
        for success, result in results:
            if not success:
                continue
            answers, _, _ = result
            hints.extend(a.payload.dottedQuad() for a in answers if a.payload.TYPE == 1)
        return DNSCurveRecursiveResolver(hints)
    return DeferredResolver(d)


def makeService():
    resolver = bootstrap(DNSCurveResolver(servers=[
        (None, '8.8.8.8', 53),
        (None, '8.8.4.4', 53)
    ], reactor=reactor))
    d = defer.Deferred()
    resolver.waiting.append(d)
    @d.addCallback
    def _resolverDone(resolver):
        log.msg('recursive resolver ready', system='dnscurve')

    ca = [CacheResolver(verbose=2)]
    cl = [
        hosts.Resolver(file='/etc/hosts'),
        resolver,
    ]

    f = server.DNSServerFactory([], ca, cl, verbose=True)
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
    elif 'cache' in event['message'][0].lower():
        event['system'] = 'dnscache'
    elif event['system'] != 'dnscurve':
        event['system'] = 'dns'
    logfile.emit(event)
application.setComponent(log.ILogObserver, filterFunc)

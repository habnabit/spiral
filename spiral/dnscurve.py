from __future__ import division

import os

from nacl.exceptions import CryptoError
from nacl.public import PublicKey, PrivateKey, Box
from twisted.names.client import Resolver as NonrecursiveResolver
from twisted.names.dns import DNSDatagramProtocol
from twisted.names.error import ResolverError
from twisted.names.root import Resolver as RecursiveResolver
from twisted.internet.defer import maybeDeferred
from twisted.python import log


class DNSCurveBase32Encoder(object):
    _digits = '0123456789bcdfghjklmnpqrstuvwxyz'

    @classmethod
    def decode(cls, data):
        ret = ''
        tmp = 0
        for e, c in enumerate(data.lower()):
            tmp = tmp | (cls._digits.index(c) << (5 * e))
        while tmp:
            ret += chr(tmp % 256)
            tmp >>= 8
        return ret

    @classmethod
    def encode(cls, data):
        ret = ''
        tmp = 0
        for e, c in enumerate(data):
            tmp = tmp | (ord(c) << (8 * e))
        while tmp:
            ret += cls._digits[tmp % 32]
            tmp >>= 5
        return ret


def getPublicKeyForHost(host):
    if not host.startswith('uz5'):
        return None
    split_host = host.split('.')
    if len(split_host[0]) != 54:
        return None
    try:
        return PublicKey(split_host[0][3:], DNSCurveBase32Encoder)
    except ValueError:
        return None


class DNSCurveDatagramProtocol(DNSDatagramProtocol):
    def __init__(self, controller, serverHosts, reactor=None):
        DNSDatagramProtocol.__init__(self, controller, reactor)
        self.serverHosts = serverHosts
        self._key = PrivateKey.generate()
        self._outstandingDNSCurveQueries = {}

    def getPublicKeyForAddress(self, address):
        host = self.serverHosts.get(address)
        if host is None:
            return None
        return getPublicKeyForHost(host)

    def writeMessage(self, message, address):
        pubkey = self.getPublicKeyForAddress(address)
        if pubkey is not None:
            log.msg('issuing DNSCurve query to', address, system='dnscurve')
            box = Box(self._key, pubkey)
            nonce = os.urandom(12)
            query = (
                'Q6fnvWj8'
                + str(self._key.public_key)
                + nonce
                + box.encrypt(message.toStr(), nonce + '\x00' * 12).ciphertext)
            self._outstandingDNSCurveQueries[nonce] = box
        else:
            query = message.toStr()
        self.transport.write(query, address)

    def datagramReceived(self, data, addr):
        if data[:8] == 'R6fnvWJ8':
            # here comes a special curve
            nonce = data[8:20]
            box = self._outstandingDNSCurveQueries.get(nonce)
            if box is None:
                return
            try:
                reply = box.decrypt(data[32:], data[8:32])
            except CryptoError:
                return
            else:
                del self._outstandingDNSCurveQueries[nonce]
        else:
            reply = data
        DNSDatagramProtocol.datagramReceived(self, reply, addr)

class DNSCurveResolver(NonrecursiveResolver):
    def __init__(self, servers, reactor):
        self.serverHosts = {}
        nonHostnameServers = []
        for host, ip, port in servers:
            self.serverHosts[ip, port] = host
            nonHostnameServers.append((ip, port))
        NonrecursiveResolver.__init__(self, servers=nonHostnameServers, reactor=reactor)

    def _connectedProtocol(self):
        proto = DNSCurveDatagramProtocol(self, self.serverHosts, reactor=self._reactor)
        self._reactor.listenUDP(0, proto)
        return proto

class DNSCurveRecursiveResolver(RecursiveResolver):
    def buildResolver(self, query, servers):
        return DNSCurveResolver(servers, reactor=self._reactor)

    def _discoveredAuthority(self, response, query, timeout, queriesLeft):
        d = maybeDeferred(RecursiveResolver._discoveredAuthority, self, response, query, timeout, queriesLeft)
        @d.addErrback
        def trapStuckError(f):
            if not f.check(ResolverError) and f.value.args[0] != (
                    "Stuck at response without answers or delegation"):
                return f
            return ([], response.authority, response.additional)
        return d

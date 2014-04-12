import collections

from twisted.internet.interfaces import IAddress
from zope.interface import implementer, Attribute


class ICurveCPAddress(IAddress):
    clientExtension = Attribute(
        "The 16-byte client extension associated with the connection.")
    serverExtension = Attribute(
        "The 16-byte server extension associated with the connection.")
    serverDomain = Attribute(
        "A string representing the server's DNS name.")
    longTermKey = Attribute(
        "A ``nacl.public.PublicKey`` representing the other side's long term public key.")
    transportHost = Attribute(
        "The host or IP of the other side of this connection.")
    transportPort = Attribute(
        "The port of the other side of this connection.")


_CurveCPAddressBase = collections.namedtuple('_CurveCPAddressBase', [
    'clientExtension', 'serverExtension', 'serverDomain', 'longTermKey',
    'transportHost', 'transportPort',
])

@implementer(ICurveCPAddress)
class CurveCPAddress(_CurveCPAddressBase):
    def asUCSPIEnv(self, requesterSide, addressSide):
        ret = {
            'PROTO': 'CURVECP',
        }
        if requesterSide == addressSide:
            ret.update({
                'CURVECPLOCALKEY': str(self.longTermKey).encode('hex'),
                'CURVECPLOCALTRANSPORT': '%s:%d' % (
                    self.transportHost, self.transportPort),
            })
        else:
            ret.update({
                'CURVECPREMOTEKEY': str(self.longTermKey).encode('hex'),
                'CURVECPREMOTETRANSPORT': '%s:%d' % (
                    self.transportHost, self.transportPort),
            })

        if requesterSide == 'client':
            ret.update({
                'CURVECPREMOTEDOMAIN': self.serverDomain,
                'CURVECPLOCALEXTENSION': self.clientExtension.encode('hex'),
                'CURVECPREMOTEEXTENSION': self.serverExtension.encode('hex'),
            })
        elif requesterSide == 'server':
            ret.update({
                'CURVECPLOCALDOMAIN': self.serverDomain,
                'CURVECPREMOTEEXTENSION': self.clientExtension.encode('hex'),
                'CURVECPLOCALEXTENSION': self.serverExtension.encode('hex'),
            })

        return ret

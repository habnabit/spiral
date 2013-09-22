import collections

from twisted.internet.interfaces import IAddress
from zope.interface import implementer, Attribute


class ICurveCPAddress(IAddress):
    clientExtension = Attribute('')
    serverExtension = Attribute('')
    serverDomain = Attribute('')
    longTermKey = Attribute('')
    transport = Attribute('')


_CurveCPAddressBase = collections.namedtuple('_CurveCPAddressBase', [
    'clientExtension', 'serverExtension', 'serverDomain', 'longTermKey',
    'transport',
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
                'CURVECPLOCALTRANSPORT': '%s:%d' % self.transport,
            })
        else:
            ret.update({
                'CURVECPREMOTEKEY': str(self.longTermKey).encode('hex'),
                'CURVECPREMOTETRANSPORT': '%s:%d' % self.transport,
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

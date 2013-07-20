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
    pass

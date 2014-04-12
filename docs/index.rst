.. include:: ../README.rst

API
===

``spiral.curvecp``
-------------------

.. module:: spiral.curvecp

.. autoclass:: CurveCPClientEndpoint(reactor, host, port, serverKey, serverExtension='\\x00' * 16, clientKey=None, clientExtension='\\x00' * 16)

.. autoclass:: CurveCPServerEndpoint(reactor, serverKey, port)


.. module:: spiral.curvecp.address

.. autointerface:: ICurveCPAddress
   :members: clientExtension, serverExtension, serverDomain, longTermKey, transport


.. automodule:: spiral.curvecp.errors
   :members: HandshakeTimeout, CurveCPConnectionDone, CurveCPConnectionFailed


``spiral.keys``
---------------

.. module:: spiral.keys

.. autointerface:: IKeyAndNonceScheme
   :members: key, nonce

.. autoclass:: Keydir

.. autoclass:: EphemeralKey


.. |CurveCPClientEndpoint| replace:: :class:`.CurveCPClientEndpoint`
.. |CurveCPServerEndpoint| replace:: :class:`.CurveCPServerEndpoint`
.. |ICurveCPAddress| replace:: :interface:`.ICurveCPAddress`
.. |IKeyAndNonceScheme| replace:: :interface:`.IKeyAndNonceScheme`

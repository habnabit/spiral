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


.. module:: spiral.curvecp.keydir

.. autointerface:: ICurveCPKey

   .. attribute:: key

      A ``nacl.public.PrivateKey`` instance.

.. autoclass:: Keydir

.. autoclass:: EphemeralKey


.. automodule:: spiral.curvecp.errors
   :members: HandshakeTimeout, CurveCPConnectionDone, CurveCPConnectionFailed


.. |CurveCPClientEndpoint| replace:: :class:`.CurveCPClientEndpoint`
.. |CurveCPServerEndpoint| replace:: :class:`.CurveCPServerEndpoint`
.. |ICurveCPAddress| replace:: :interface:`.ICurveCPAddress`
.. |IKeydir| replace:: :interface:`.IKeydir`
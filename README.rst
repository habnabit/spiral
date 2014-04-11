======
spiral
======


A `twisted`_ curve is a spiral.

``spiral`` is a collection of elliptic-curve-backed protocol implementations.
At the moment,
this is limited to `DNSCurve`_ and `CurveCP`_.


DNSCurve
========

DNSCurve support is experimental and requires a currently-unmerged branch of Twisted.
Client recursive and nonrecursive resolvers have been implemented;
there is currently no DNSCurve server support.


CurveCP
=======

CurveCP support comes in two forms:


``curvecpmclient`` and ``curvecpmserver``
-----------------------------------------

``curvecpmclient`` and ``curvecpmserver`` are `UCSPI`_\ -style executables.
``curvecpmclient`` will connect to a given CurveCP server and spawn a process to communicate with it.
``curvecpmserver`` will listen on a particular port and spawn a process for each incoming connection.


Endpoints
---------

Two standard `twisted endpoints`_ are exposed for writing clients or servers in python:
|CurveCPClientEndpoint| and |CurveCPServerEndpoint|.


.. _twisted: http://twistedmatrix.com/
.. _twisted endpoints: http://twistedmatrix.com/documents/current/core/howto/endpoints.html
.. _CurveCP: http://curvecp.org/
.. _DNSCurve: http://dnscurve.org/
.. _UCSPI: http://cr.yp.to/proto/ucspi.txt

.. |CurveCPClientEndpoint| replace:: ``CurveCPClientEndpoint``
.. |CurveCPServerEndpoint| replace:: ``CurveCPServerEndpoint``

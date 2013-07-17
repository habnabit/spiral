import os

from nacl.public import PrivateKey
from twisted.internet.protocol import DatagramProtocol
from twisted.python import log

from spiral.curvecp._libcurvecpr import C, ffi
from spiral.nonce import nonceSource


@ffi.callback('int(struct curvecpr_client *client, unsigned char *destination, size_t num)')
def nextNonce(client, dest, num):
    print 'squeezing', num, 'bytes for', client, dest
    ffi.buffer(dest, num)[:] = nonceSource.squeeze(num)
    return 0


class CurveCPTransport(DatagramProtocol):
    def __init__(self, host, port, serverKey, serverExtension, clientKey=None, clientExtension='\x00' * 16):
        self.client = ffi.new('struct curvecpr_client[1]')
        self.cf = ffi.new('struct curvecpr_client_cf[1]')
        self.host = host
        self.port = port
        self.serverKey = serverKey
        self.serverExtension = serverExtension
        if clientKey is None:
            clientKey = PrivateKey.generate()
        self.clientKey = clientKey
        self.clientExtension = clientExtension
        self.setupClient()

    def setupClient(self):
        self.setupClientFunctions()

        self.cf[0].my_extension = self.clientExtension
        self.cf[0].my_global_pk = str(self.clientKey.public_key)
        self.cf[0].my_global_sk = str(self.clientKey)

        self.cf[0].their_extension = self.serverExtension
        self.cf[0].their_global_pk = str(self.serverKey)
        self.cf[0].their_domain_name = 'example\0com\0'

        C.curvecpr_client_new(self.client, self.cf)

    def setupClientFunctions(self):
        self._funcs = []

        self.cf[0].ops.next_nonce = nextNonce

        @ffi.callback('int(struct curvecpr_client *client, const unsigned char *buf, size_t num)')
        def send(client, buf, num):
            print 'writing', num, 'bytes'
            try:
                self.transport.write(ffi.buffer(buf, num)[:], (self.host, self.port))
            except Exception:
                log.err(None, 'error sending curvecp datagram')
                return -1
            else:
                return 0

        self.cf[0].ops.send = send
        self._funcs.append(send)

        @ffi.callback('int(struct curvecpr_client *client, const unsigned char *buf, size_t num)')
        def recv(client, buf, num):
            print 'want', num, 'bytes'

        self.cf[0].ops.recv = recv
        self._funcs.append(recv)

    def startProtocol(self):
        C.curvecpr_client_connected(self.client)

    def datagramReceived(self, data, host_port):
        print 'got', len(data), 'bytes'
        C.curvecpr_client_recv(self.client, data, len(data))

    def write(self, data):
        print 'writing', `data`
        ret = C.curvecpr_client_send(self.client, data, len(data))
        if ret:
            print os.strerror(-ret)

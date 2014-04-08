import os

from nacl.public import PrivateKey
from twisted.internet.protocol import DatagramProtocol
from twisted.python import log

from spiral.curvecp._c_libcurvecpr import C, ffi


CLIENT_PENDING, CLIENT_INITIATING, CLIENT_NEGOTIATED = range(3)
BLOCK_STREAM, BLOCK_EOF_FAILURE, BLOCK_EOF_SUCCESS = range(3)
NS = 1e9


@ffi.callback('int(struct curvecpr_client_messager_glib *, unsigned char *, size_t)')
def nextNonce(client, dest, num):
    print 'squeezing', num, 'bytes for', client, dest
    ffi.buffer(dest, num)[:] = os.urandom(num)
    return 0


class CurveCPTransport(DatagramProtocol):
    def __init__(self, reactor, host, port, serverKey, serverExtension, clientKey=None, clientExtension='\x00' * 16):
        self.reactor = reactor
        self.host = host
        self.port = port
        self.serverKey = serverKey
        self.serverExtension = serverExtension
        if clientKey is None:
            clientKey = PrivateKey.generate()
        self.clientKey = clientKey
        self.clientExtension = clientExtension
        self._funcs = []
        self.setupClient()
        self.delayedCall = None

    def setupClient(self):
        self.client = ffi.new('struct curvecpr_client_messager_glib *')
        self.setupClientFunctions()

        self.client_cf.pending_maximum = 2 ** 32
        self.client_cf.sendmarkq_maximum = 2 ** 16
        self.client_cf.recvmarkq_maximum = 2 ** 16

        self.client_cf[0].my_extension = self.clientExtension
        self.client_cf[0].my_global_pk = str(self.clientKey.public_key)
        self.client_cf[0].my_global_sk = str(self.clientKey)

        self.client_cf[0].their_extension = self.serverExtension
        self.client_cf[0].their_global_pk = str(self.serverKey)
        C.curvecpr_util_encode_domain_name(self.client_cf[0].their_domain_name, 'example.com')

        C.curvecpr_client_messager_glib_new(self.client, self.client_cf)

    def setupClientFunctions(self):
        self.client_cf = ffi.new('struct curvecpr_client_messager_glib_cf *')

        @ffi.callback('int(struct curvecpr_client_messager_glib *, const unsigned char *, size_t)')
        def send(client, buf, num):
            print 'writing', num, 'bytes'
            try:
                self.transport.write(ffi.buffer(buf, num)[:], (self.host, self.port))
            except Exception:
                log.err(None, 'error sending curvecp datagram')
                return -1
            else:
                return 0

        self._funcs.append(send)

        @ffi.callback('int(struct curvecpr_client_messager_glib *, const unsigned char *, size_t)')
        def recv(client, buf, num):
            print 'got', num, 'bytes', `ffi.buffer(buf, num)[:]`
            return 0

        self._funcs.append(recv)

        @ffi.callback('void(struct curvecpr_client_messager_glib *, enum curvecpr_block_eofflag)')
        def finished(client, flag):
            print 'finished', flag
            C.curvecpr_client_messager_glib_finish(self.client)

        self._funcs.append(finished)

        self.client_cf = ffi.new('struct curvecpr_client_messager_glib_cf *', {
            'ops': {
                'send': send,
                'recv': recv,
                'finished': finished,
                'next_nonce': nextNonce,
            },
        })

    def startProtocol(self):
        C.curvecpr_client_messager_glib_connected(self.client)

    def datagramReceived(self, data, host_port):
        print 'got', len(data), 'bytes'
        C.curvecpr_client_messager_glib_recv(self.client, data, len(data))
        if self.client[0].client.negotiated != CLIENT_PENDING:
            self._processSendQ()

    def write(self, data):
        ret = C.curvecpr_client_messager_glib_send(self.client, data, len(data))
        if ret:
            print os.strerror(-ret)
        self.reschedule()

    def _processSendQ(self):
        if self.client[0].client.negotiated != CLIENT_PENDING:
            C.curvecpr_client_messager_glib_process_sendq(self.client)
        self.reschedule()

    def reschedule(self):
        nextActionIn = C.curvecpr_client_messager_glib_next_timeout(self.client) / NS
        if self.delayedCall is not None and self.delayedCall.active():
            self.delayedCall.reset(nextActionIn)
        else:
            self.delayedCall = self.reactor.callLater(
                nextActionIn, self._processSendQ)

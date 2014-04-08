import os
import struct

from nacl.exceptions import CryptoError
from nacl.public import Box, PrivateKey, PublicKey
from nacl.secret import SecretBox
from twisted.internet.protocol import DatagramProtocol
from twisted.python import log

from spiral.curvecp._pynacl.transport import CurveCPServerTransport
from spiral.curvecp.util import dnsToName


_nonceStruct = struct.Struct('!Q')
_helloStruct = struct.Struct('<8x16s16s32s64x8s80s')
_initiateStruct = struct.Struct('<8x16x16x32x16s80s8s')
_initiateInnerStruct = struct.Struct('<32s16s48s256s')


class CurveCPServerDispatcher(DatagramProtocol):
    def __init__(self, reactor, serverKey, factory):
        self.reactor = reactor
        self.serverKey = serverKey
        self.factory = factory
        self.transports = {}
        self._secretBox = SecretBox(os.urandom(SecretBox.KEY_SIZE))

    def _replyWithCookie(self, data, host_port):
        if len(data) != _helloStruct.size:
            return
        serverExtension, clientExtension, clientShortPubkey, nonce, encrypted = _helloStruct.unpack(data)
        serverLongClientShort = Box(self.serverKey.key, PublicKey(clientShortPubkey))
        try:
            serverLongClientShort.decrypt(encrypted, 'CurveCP-client-H' + nonce)
        except CryptoError:
            return
        serverShortKey = PrivateKey.generate()
        unencryptedCookie = clientShortPubkey + str(serverShortKey)
        cookieNonce = self.serverKey.nonce(longterm=True)
        cookie = cookieNonce + self._secretBox.encrypt(unencryptedCookie, 'c' * 8 + cookieNonce).ciphertext
        boxData = str(serverShortKey.public_key) + cookie
        cookiePacket = (
            'RL3aNMXK'
            + clientExtension
            + serverExtension
            + cookieNonce
            + serverLongClientShort.encrypt(boxData, 'CurveCPK' + cookieNonce).ciphertext)
        self.transport.write(cookiePacket, host_port)

    def _checkInitiate(self, clientID, data, host_port):
        cookieNonce, encryptedCookie, nonce = _initiateStruct.unpack_from(data)
        try:
            decryptedCookie = self._secretBox.decrypt(encryptedCookie, 'c' * 8 + cookieNonce)
        except CryptoError:
            return
        clientShortPubkey = PublicKey(decryptedCookie[:32])
        serverShortKey = PrivateKey(decryptedCookie[32:])
        serverShortClientShort = Box(serverShortKey, clientShortPubkey)
        try:
            decrypted = serverShortClientShort.decrypt(data[176:], 'CurveCP-client-I' + nonce)
        except CryptoError:
            return
        clientPubkeyString, vouchNonce, encryptedVouch, serverDomain = _initiateInnerStruct.unpack_from(decrypted)
        clientPubkey = PublicKey(clientPubkeyString)
        serverLongClientLong = Box(self.serverKey.key, clientPubkey)
        try:
            vouchKey = serverLongClientLong.decrypt(encryptedVouch, 'CurveCPV' + vouchNonce)
        except CryptoError:
            return
        if vouchKey != str(clientShortPubkey):
            return
        transport = CurveCPServerTransport(
            self.reactor, self.serverKey, self.factory, clientID,
            clientPubkey, host_port, serverShortClientShort, dnsToName(serverDomain))
        return transport, decrypted[352:]

    def datagramReceived(self, data, host_port):
        l = len(data)
        if l < 80 or l > 1184 or l & 0xf:
            return

        if data[:8] == 'QvnQ5XlH':
            self._replyWithCookie(data, host_port)
            return

        clientID = data[8:72]
        if clientID in self.transports:
            self.transports[clientID].datagramReceived(data, host_port)
            return

        if data[:8] != 'QvnQ5XlI':
            return
        result = self._checkInitiate(clientID, data, host_port)
        if result is None:
            return
        log.msg('new client: %s' % clientID.encode('hex'), category='success')
        transport, message = result
        self.transports[clientID] = transport
        transport.transport = self.transport
        transport.startProtocol()
        transport._parseMessage(transport._now(), message)
        transport.notifyFinish().addCallback(self._clientFinished, clientID)

    def _clientFinished(self, ign, clientID):
        del self.transports[clientID]

import fcntl
import os
import struct

from nacl.public import PrivateKey


counterStruct = struct.Struct('<Q')


class Keydir(object):
    def __init__(self, keydir):
        self.keydir = keydir
        with open(self.expertsFile('secretkey')) as infile:
            self.key = PrivateKey(infile.read())

    def expertsFile(self, name):
        return os.path.join(self.keydir, '.expertsonly', name)

    def nonce(self, longterm=False):
        with open(self.expertsFile('lock'), 'r+') as lockfile:
            fcntl.lockf(lockfile, fcntl.LOCK_EX)
            with open(self.expertsFile('noncecounter'), 'rb+') as noncefile:
                data = noncefile.read()
                counter, = counterStruct.unpack(data)
                counter += 1048576 if longterm else 1
                noncefile.seek(0)
                data = counterStruct.pack(counter)
                noncefile.write(data)
        return os.urandom(8) + data


class EphemeralKey(object):
    def __init__(self):
        self.key = PrivateKey.generate()

    def nonce(self, longterm=False):
        return os.urandom(16)

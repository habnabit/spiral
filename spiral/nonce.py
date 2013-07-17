import os

from keccak import Sponge


nonceSource = Sponge(1152, 448)
nonceSource.absorb(os.urandom(64))

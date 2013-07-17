import os

from keccak import Sponge, SpongeRandom


nonceSource = Sponge(1152, 448)
nonceSource.absorb(os.urandom(64))
random = SpongeRandom(nonceSource)

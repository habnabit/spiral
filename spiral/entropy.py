import os

from keccak import Sponge, SpongeRandom


sponge = Sponge(1152, 448)
sponge.absorb(os.urandom(64))
random = SpongeRandom(sponge)

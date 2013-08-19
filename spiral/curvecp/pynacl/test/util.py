def runUntilNext(clock):
    nextCallTime = min(c.getTime() for c in clock.getDelayedCalls())
    clock.advance(nextCallTime - clock.seconds())

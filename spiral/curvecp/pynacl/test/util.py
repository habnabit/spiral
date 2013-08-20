def nextCallTime(clock):
    return min(c.getTime() for c in clock.getDelayedCalls())

def runUntilNext(clock):
    clock.advance(nextCallTime(clock) - clock.seconds())

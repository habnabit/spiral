def nextCallIn(clock):
    return min(c.getTime() for c in clock.getDelayedCalls()) - clock.seconds()

def runUntilNext(clock):
    clock.advance(nextCallIn(clock))

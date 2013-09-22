class MultiTimeout(object):
    def __init__(self, clock, timeouts, onFinalTimeout, f, *a, **kw):
        self.clock = clock
        self.timeouts = list(timeouts)
        self.onFinalTimeout = onFinalTimeout
        self.f = f
        self.a = a
        self.kw = kw
        self.calls = []

    def reset(self):
        self.cancel()
        self.calls = []
        self.f(*self.a, **self.kw)
        fullDelay = 0
        for timeout in self.timeouts[:-1]:
            fullDelay += timeout
            self.calls.append(self.clock.callLater(fullDelay, self.f, *self.a, **self.kw))
        fullDelay += self.timeouts[-1]
        self.calls.append(self.clock.callLater(fullDelay, self.onFinalTimeout))

    def cancel(self):
        for call in self.calls:
            if call.active():
                call.cancel()

from interval import Interval


def halfOpen(l, u):
    return Interval(l, u, upper_closed=False)

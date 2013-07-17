import collections
import itertools
import struct

from parsley import makeGrammar

from spiral.curvecp.pynacl.interval import halfOpen


_uint16 = struct.Struct('<H')
_uint32 = struct.Struct('<I')
_uint64 = struct.Struct('<Q')


_MessageBase = collections.namedtuple('_Message', [
    'id', 'previousID', 'ranges', 'resolution', 'dataPos', 'data',
])


class Message(_MessageBase):
    sizes = [192, 320, 576, 1024]
    resolutions = {'success': 0x800, 'failure': 0x1000}

    def pack_data(self):
        for size in self.sizes:
            if len(self.data) > size:
                continue
            data = self.data.rjust(size, '\x00')
            status = (
                self.resolutions.get(self.resolution, 0)
                | len(self.data))
            return _uint16.pack(status) + _uint64.pack(self.dataPos) + data
        raise ValueError(
            'data is %d bytes when the limit is %d' % (len(self.data), size))

    rangePackers = [
        (None, _uint64),
        (_uint32, _uint16),
        (_uint16, _uint16),
        (_uint16, _uint16),
        (_uint16, _uint16),
        (_uint16, _uint16),
    ]

    def pack_ranges(self):
        ret = []
        prev = 0
        ranges = self.ranges
        if ranges and ranges[0].lower_bound != 0:
            ranges = [halfOpen(0, 0)] + ranges[:5]
        izip = itertools.izip_longest(
            ranges, self.rangePackers, fillvalue=None)
        for i, (deltaPack, spanPack) in izip:
            i = i or halfOpen(prev, prev)
            if not i.lower_closed or i.upper_closed:
                raise ValueError('every interval must be half-open')
            if deltaPack is None and i.lower_bound != 0:

                raise ValueError('first interval must start at 0')
            if deltaPack is not None:
                ret.append(deltaPack.pack(i.lower_bound - prev))
                prev = i.lower_bound
            ret.append(spanPack.pack(i.upper_bound - prev))
            prev = i.upper_bound
        return ''.join(ret)

    def pack(self):
        return (
            _uint32.pack(self.id)
            + _uint32.pack(self.previousID)
            + self.pack_ranges()
            + self.pack_data())


def _makeIntervals(ranges):
    end = 0
    ret = []
    for delta, span in ranges:
        start = end + delta
        end = start + span
        if start == end:
            continue
        ret.append(halfOpen(start, end))
    return ret


messageGrammar = """

uint16 = <anything{2}>:x -> _uint16.unpack(x)[0]
uint32 = <anything{4}>:x -> _uint32.unpack(x)[0]
uint64 = <anything{8}>:x -> _uint64.unpack(x)[0]

range16 = uint16:delta uint16:span -> (delta, span)
spans = (uint64:firstRangeSpan uint32:secondRangeDelta
    uint16:secondRangeSpan range16:third range16:fourth range16:fifth
    range16:sixth) -> makeIntervals([
        (0, firstRangeSpan), (secondRangeDelta, secondRangeSpan), third,
        fourth, fifth, sixth])

status = uint16:raw -> (raw & 0x7ff, 'success' if raw & 0x800 else 'failure' if raw & 0x1000 else None)

message = (uint32:id uint32:previous spans:spans
    status:(length, resolution) uint64:dataPos '\x00'* <anything{length}>:data end) -> Message(
    id, previous, spans, resolution, dataPos, data
)

"""

_bindings = dict(
    _uint16=_uint16,
    _uint32=_uint32,
    _uint64=_uint64,
    Message=Message,
    makeIntervals=_makeIntervals,
)

messageParser = makeGrammar(messageGrammar, _bindings)

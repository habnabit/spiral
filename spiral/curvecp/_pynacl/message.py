import collections
import itertools
import struct

from spiral.curvecp._pynacl.interval import halfOpen


_uint16 = struct.Struct('<H')
_uint32 = struct.Struct('<I')
_uint64 = struct.Struct('<Q')
_maxima = {s: s.unpack('\xff' * s.size)[0] for s in [_uint16, _uint32, _uint64]}

def packInto(s, val, target):
    maximum = _maxima[s]
    if val > maximum:
        target.append('\xff' * s.size)
        return val - maximum
    else:
        target.append(s.pack(val)),
        return 0


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
        rangeIter = iter(ranges)
        remainingDelta = remainingSpan = None
        for deltaPack, spanPack in self.rangePackers:
            if not (remainingSpan or remainingDelta):
                i = next(rangeIter, None) or halfOpen(prev, prev)
                if not i.lower_closed or i.upper_closed:
                    raise ValueError('every interval must be half-open')
                if deltaPack is None and i.lower_bound != 0:
                    raise ValueError('first interval must start at 0')
                remainingDelta = i.lower_bound - prev
                remainingSpan = i.upper_bound - i.lower_bound
                prev = i.upper_bound
            if deltaPack is not None:
                remainingDelta = packInto(deltaPack, remainingDelta, ret)
            if not remainingDelta:
                remainingSpan = packInto(spanPack, remainingSpan, ret)
            else:
                packInto(spanPack, 0, ret)
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


# 0. 4 bytes: a message ID chosen by the sender.
# 1. 4 bytes: if nonzero, a message ID received by the sender immediately
#             before this message was sent.
# 2. 8 bytes: a 64-bit unsigned integer in little-endian form, the number of
#             bytes in the first range being acknowledged as part of this
#             message. A range can include 0 bytes, in which case it does not
#             actually acknowledge anything.
# 3. 4 bytes: a 32-bit unsigned integer in little-endian form, the number of
#             bytes between the first range and the second range.
# 4. 2 bytes: a 16-bit unsigned integer in little-endian form, the number of
#             bytes in the second range.
# 5. 2 bytes: a 16-bit unsigned integer in little-endian form, the number of
#             bytes between the second range and the third range.
# 6. 2 bytes: a 16-bit unsigned integer in little-endian form, the number of
#             bytes in the third range.
# 7. 2 bytes: a 16-bit unsigned integer in little-endian form, the number of
#             bytes between the third range and the fourth range.
# 8. 2 bytes: a 16-bit unsigned integer in little-endian form, the number of
#             bytes in the fourth range.
# 9. 2 bytes: a 16-bit unsigned integer in little-endian form, the number of
#             bytes between the fourth range and the fifth range.
# 10. 2 bytes: a 16-bit unsigned integer in little-endian form, the number of
#              bytes in the fifth range.
# 11. 2 bytes: a 16-bit unsigned integer in little-endian form, the number of
#              bytes between the fifth range and the sixth range.
# 12. 2 bytes: a 16-bit unsigned integer in little-endian form, the number of
#              bytes in the sixth range.
# 13. 2 bytes: a 16-bit unsigned integer in little-endian form, the sum of the
#              following integers:
#               - D, an integer between 0 and 1024, the size of the data block
#                 being sent as part of this message.
#               - SUCC, either 0 or 2048, where 2048 means that this block is
#                 known to be at the end of the stream followed by success.
#               - FAIL, either 0 or 4096, where 4096 means that this block is
#                 known to be at the end of the stream followed by failure.
# 14. 8 bytes: a 64-bit unsigned integer in little-endian form, the position of
#              the first byte in the data block being sent. If D=0 but SUCC>0
#              or FAIL>0 then this is the success/failure position, i.e., the
#              total number of bytes in the stream.

messageStruct = struct.Struct('<IIQI10HQ')
def parseMessage(s):
    unpacked = messageStruct.unpack_from(s)
    rawRanges = unpacked[2:13]
    it = itertools.chain([0], rawRanges)
    intervals = _makeIntervals(zip(it, it))
    rawStatus = unpacked[13]
    length = rawStatus & 0x7ff
    resolution = 'success' if rawStatus & 0x800 else 'failure' if rawStatus & 0x1000 else None
    if not length:
        data = ''
    else:
        data = s[-length:]
    return Message(
        unpacked[0], unpacked[1], intervals, resolution, unpacked[14], data,
    )

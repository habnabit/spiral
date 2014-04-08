import pytest

from spiral.curvecp._pynacl.message import Message
from spiral.curvecp._pynacl.interval import halfOpen


messagePackPairs = [
    (Message(0, 0, [], None, 0, ''), '\0' * 202),
    (Message(0, 0, [], 'success', 0, ''), '\0\10' + '\0' * 200),
    (Message(0, 0, [], 'failure', 0, ''), '\0\20' + '\0' * 200),
    (Message(0, 0, [], None, 0, '\1'), '\1\0' + '\0' * 199 + '\1'),
    (Message(0, 0, [], None, 0, '\0' * 193), '\xc1\0' + '\0' * 328),
    (Message(0, 0, [], None, 0, '\1' * 193), '\xc1\0' + '\0' * 135 + '\1' * 193),
    (Message(0, 0, [], None, 0, '\0' * 321), '\x41\1' + '\0' * 584),
    (Message(0, 0, [], None, 0, '\1' * 321), '\x41\1' + '\0' * 263 + '\1' * 321),
    (Message(0, 0, [], None, 0, '\0' * 577), '\x41\2' + '\0' * 1032),
    (Message(0, 0, [], None, 0, '\1' * 577), '\x41\2' + '\0' * 455 + '\1' * 577),
    (Message(0, 0, [], None, 0, '\1' * 1024), '\0\4' + '\0' * 8 + '\1' * 1024),
    (Message(0, 0, [], 'success', 0, '\1' * 1024), '\0\14' + '\0' * 8 + '\1' * 1024),
    (Message(0, 0, [], 'failure', 0, '\1' * 1024), '\0\24' + '\0' * 8 + '\1' * 1024),
]

@pytest.mark.parametrize(('input', 'expected'), messagePackPairs)
def test_messagePack(input, expected):
    assert input.pack_data().encode('hex') == expected.encode('hex')

def test_messagePackFailure():
    m = Message(0, 0, [], None, 0, '\0' * 1025)
    with pytest.raises(ValueError):
        m.pack_data()

messagePackRangesPairs = [
    ([], '\0' * 30),
    ([halfOpen(0, 256)], '\0\1\0\0\0\0\0\0' + '\0' * 22),
    ([halfOpen(0, 257)],  '\1\1\0\0\0\0\0\0' + '\0' * 22),
    ([halfOpen(0, 256), halfOpen(512, 1024)], '\0\1\0\0\0\0\0\0' + '\0\1\0\0' + '\0\2' + '\0' * 16),
    ([
        halfOpen(0, 18446744073709551615),
        halfOpen(18446744078004518910, 18446744078004584445),
        halfOpen(18446744078004649980, 18446744078004715515),
        halfOpen(18446744078004781050, 18446744078004846585),
        halfOpen(18446744078004912120, 18446744078004977655),
        halfOpen(18446744078005043190, 18446744078005108725)
    ], '\xff' * 30),

    # overflows
    ([halfOpen(0, 18446744073709551616)], '\xff' * 8 + '\0\0\0\0\1\0' + '\0' * 16),
    ([halfOpen(0, 18446744073709879290)], '\xff' * 8 + '\0\0\0\0\xff\xff' + '\0\0\xff\xff' * 4),
    ([halfOpen(0, 1), halfOpen(2, 65540)], '\1\0\0\0\0\0\0\0' '\1\0\0\0\xff\xff' '\0\0\3\0' + '\0' * 12),
    ([halfOpen(0, 1), halfOpen(2, 3), halfOpen(65540, 65541)],
     '\1\0\0\0\0\0\0\0' '\1\0\0\0\1\0' '\xff\xff\0\0' '\2\0\1\0' + '\0' * 8),
    ([halfOpen(0, 1), halfOpen(2, 327676)],
     '\1\0\0\0\0\0\0\0' '\1\0\0\0\xff\xff' + '\0\0\xff\xff' * 3 + '\0\0\xfe\xff'),
]

@pytest.mark.parametrize(('input', 'expected'), messagePackRangesPairs)
def test_messagePackRanges(input, expected):
    assert Message(0, 0, input, None, 0, '').pack_ranges().encode('hex') == expected.encode('hex')

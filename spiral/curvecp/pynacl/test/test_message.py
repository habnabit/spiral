import pytest

from spiral.curvecp.pynacl.message import Message
from spiral.curvecp.pynacl.interval import halfOpen


def testMessage_pack_data():
    m = Message(0, 0, [], None, 0, '')
    assert m.pack_data() == '\0' * 202

    m = Message(0, 0, [], 'success', 0, '')
    assert m.pack_data() == '\0\10' + '\0' * 200

    m = Message(0, 0, [], 'failure', 0, '')
    assert m.pack_data() == '\0\20' + '\0' * 200

    m = Message(0, 0, [], None, 0, '\1')
    assert m.pack_data() == '\1\0' + '\0' * 199 + '\1'

    m = Message(0, 0, [], None, 0, '\0' * 193)
    assert m.pack_data() == '\xc1\0' + '\0' * 328

    m = Message(0, 0, [], None, 0, '\1' * 193)
    assert m.pack_data() == '\xc1\0' + '\0' * 135 + '\1' * 193

    m = Message(0, 0, [], None, 0, '\0' * 321)
    assert m.pack_data() == '\x41\1' + '\0' * 584

    m = Message(0, 0, [], None, 0, '\1' * 321)
    assert m.pack_data() == '\x41\1' + '\0' * 263 + '\1' * 321

    m = Message(0, 0, [], None, 0, '\0' * 577)
    assert m.pack_data() == '\x41\2' + '\0' * 1032

    m = Message(0, 0, [], None, 0, '\1' * 577)
    assert m.pack_data() == '\x41\2' + '\0' * 455 + '\1' * 577

    m = Message(0, 0, [], None, 0, '\1' * 1024)
    assert m.pack_data() == '\0\4' + '\0' * 8 + '\1' * 1024

    m = Message(0, 0, [], 'success', 0, '\1' * 1024)
    assert m.pack_data() == '\0\14' + '\0' * 8 + '\1' * 1024

    m = Message(0, 0, [], 'failure', 0, '\1' * 1024)
    assert m.pack_data() == '\0\24' + '\0' * 8 + '\1' * 1024

    m = Message(0, 0, [], None, 0, '\0' * 1025)
    with pytest.raises(ValueError):
        m.pack_data()

def testMessage_pack_ranges():
    m = Message(0, 0, [], None, 0, '')
    assert m.pack_ranges() == '\0' * 30

    m = Message(0, 0, [halfOpen(0, 256)], None, 0, '')
    assert m.pack_ranges() == '\0\1\0\0\0\0\0\0' + '\0' * 22

    m = Message(0, 0, [halfOpen(0, 257)], None, 0, '')
    assert m.pack_ranges() == '\1\1\0\0\0\0\0\0' + '\0' * 22

    m = Message(0, 0, [halfOpen(0, 256), halfOpen(512, 1024)], None, 0, '')
    assert m.pack_ranges() == '\0\1\0\0\0\0\0\0' + '\0\1\0\0' + '\0\2' + '\0' * 16

    m = Message(0, 0, [
        halfOpen(0, 18446744073709551615),
        halfOpen(18446744078004518910, 18446744078004584445),
        halfOpen(18446744078004649980, 18446744078004715515),
        halfOpen(18446744078004781050, 18446744078004846585),
        halfOpen(18446744078004912120, 18446744078004977655),
        halfOpen(18446744078005043190, 18446744078005108725)
    ], None, 0, '')
    assert m.pack_ranges() == '\xff' * 30

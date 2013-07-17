from spiral.dnscurve import DNSCurveBase32Encoder


known_pairs = [
    ('\x64\x88', '4321'),
    ('5436f78cecb9ead999f5e236def711311cbb319d7aa7f8d3649161ee04d8e035'.decode('hex'),
     'nlfgh6lxtpumxdqy2rfwxv72k17qvsnmuv9kz9mdkdswg20v0hf'),
    ('cb5cb4ab9c12a0928b157ff5990650c9d4d6ad8b23e9c74a60e77e782f5b5c4a'.decode('hex'),
     'c6r8vplml085t5q2zcxm930b96pfxqgk39uhd51d7rzjrrdcwll'),
    ('8a91b0788d029de7fbf33d831e544bf9f7a89e6e55383cb3e61aa67acae39867'.decode('hex'),
     'bd41cwpk287hyxhyxt0x1bf9tzxkbhufp2gsmtuwuj9p75hwswt'),
]

def test_encode():
    for decoded, encoded in known_pairs:
        assert DNSCurveBase32Encoder.encode(decoded) == encoded

def test_decode():
    for decoded, encoded in known_pairs:
        assert DNSCurveBase32Encoder.decode(encoded) == decoded

def test_roundtrip():
    assert DNSCurveBase32Encoder.decode(DNSCurveBase32Encoder.encode('spam eggs spam spam')) == 'spam eggs spam spam'

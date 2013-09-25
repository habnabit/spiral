def nameToDNS(name):
    ret = []
    for part in name.strip('.').split('.'):
        ret.extend([chr(len(part)), part])
    return ''.join(ret).ljust(256, '\0')

def dnsToName(dns):
    pos = 0
    ret = []
    while pos < 256:
        length = ord(dns[pos:pos + 1])
        if not length:
            break
        ret.append(dns[pos + 1:pos + 1 + length])
        pos += 1 + length
    return '.'.join(ret)

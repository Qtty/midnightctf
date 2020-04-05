import string, sys, hashlib, binascii
from Crypto.Cipher import AES
from flag import key


if not len(key) == 42:
    raise AssertionError
else:
    data = open(sys.argv[1], 'rb').read()
    assert len(data) >= 191


FIBOFFSET = 4919
MAXFIBSIZE = 42 + len(data) + FIBOFFSET

def fibseq(n):
    out = [0, 1]
    for i in range(2, n):
        out += [out[(i - 1)] + out[(i - 2)]]
    return out


FIB = fibseq(MAXFIBSIZE)
i = 0
output = ''
len_data = len(data)
while i < len_data:
    data1 = data[FIB[i] % len_data]
    key1 = key[(i + FIB[FIBOFFSET + i]) % 42]
    i += 1

    data2 = data[FIB[i] % len_data]
    key2 = key[(i + FIB[FIBOFFSET + i]) % 42]
    i += 1

    tohash = bytes([data1, data2])
    toencrypt = bytes(hashlib.md5(tohash).hexdigest(), encoding='utf-8')

    thiskey = bytes([key1, key2]) * 16
    cipher = AES.new(thiskey, AES.MODE_ECB)
    enc = cipher.encrypt(toencrypt)

    output += binascii.hexlify(enc).decode('ascii')
print(output)

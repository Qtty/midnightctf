#!/usr/bin/python2

from Crypto.Cipher import AES
from hashlib import md5


def fibseq(n):
    out = [0, 1]
    for i in range(2, n):
        out += [out[(i - 1)] + out[(i - 2)]]
    return out

FIBOFFSET = 4919

with open('hash.txt', 'r') as f:
    hash = f.read().rstrip().decode('hex')

possible_keys = []

for i in range(256):
    for j in range(256):
        possible_keys.append((chr(i) + chr(j)) * 16)

blocks = [hash[i: i + 32] for i in range(0, len(hash), 32)]
key_blocks = []

for n, block in enumerate(blocks):
    for thiskey in possible_keys:
        cipher = AES.new(thiskey, AES.MODE_ECB)
        tmp = cipher.decrypt(block)

        try:
            tmp.decode('hex')
            print (tmp, thiskey, n)
            key_blocks.append(thiskey[:2])
            break
        except:
            pass

len_data = len(blocks) * 2
MAXFIBSIZE = 42 + len_data + FIBOFFSET
FIB = fibseq(MAXFIBSIZE)

key = ''
key_positions = []
for i in range(0, len_data, 2):
    key_positions.append(((i + FIB[FIBOFFSET + i]) % 42, (i + 1 + FIB[FIBOFFSET + i + 1]) % 42))

for i in range(42):
    for n, pos in enumerate(key_positions):
        if i == pos[0]:
            p = 0
            break
        elif i == pos[1]:
            p = 1
            break
    key += key_blocks[n][p]

print(key)
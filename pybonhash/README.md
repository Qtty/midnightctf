# PyBonHash

In this challenge we're given two files: 
* `hash.txt`: a file containing the hex encoded hash
* `pybonhash.cpython-36.pyc`: a compiled version of the python script responsible of the hashing

unlike assembly, python byte code can be decompiled with precision, meaning that the decompiled script is (almost)identical to the original script, after a quick google search, i found a decompiler called [uncompyle6](https://github.com/rocky/python-uncompyle6/), it worked perfectly and yielded this script:
```python
import string, sys, hashlib, binascii
from Crypto.Cipher import AES
from flag import key

if not len(key) == 42:
    raise AssertionError
else:
    data = open(sys.argv[1], 'rb').read()
    assert len(data) >= 191
FIBOFFSET = 4919
MAXFIBSIZE = len(key) + len(data) + FIBOFFSET

def fibseq(n):
    out = [
     0, 1]
    for i in range(2, n):
        out += [out[(i - 1)] + out[(i - 2)]]

    return out


FIB = fibseq(MAXFIBSIZE)
i = 0
output = ''
while i < len(data):
    data1 = data[(FIB[i] % len(data))]
    key1 = key[((i + FIB[(FIBOFFSET + i)]) % len(key))]
    i += 1
    data2 = data[(FIB[i] % len(data))]
    key2 = key[((i + FIB[(FIBOFFSET + i)]) % len(key))]
    i += 1
    tohash = bytes([data1, data2])
    toencrypt = hashlib.md5(tohash).hexdigest()
    thiskey = bytes([key1, key2]) * 16
    cipher = AES.new(thiskey, AES.MODE_ECB)
    enc = cipher.encrypt(toencrypt)
    output += binascii.hexlify(enc).decode('ascii')

print(output)
```

looking at the script, we can easily understarnd how the hashing process is done:
1. the `hashing key` has a fixed length of 42
2. data length >= 191
3. it generates a Fibonacci sequence of `MAXFIBSIZE` terms where `MAXFIBSIZE == 4961 + len(data)`
4. it loops `range(0, len(data), 2)` times, doing the following:
    1. choose two bytes from the data with the following positions:
    ```python
    FIB[i] % len(data), (FIB[i + 1] % len(data))
    ```
    2. choose two bytes from the key with the following positions:
    ```python
    (i + FIB[FIBOFFSET + i]) % 42, (i + 1 + FIB[FIBOFFSET + i + 1]) % 42
    ```
    3. hash the concat of the two data bytes using md5
    4. create an encryption key that is the concat of the two key bytes repeated 16 times
    5. encrypts the hex encoded md5 hash using AES in ECB mode

now, we know that the encrypted data is hex encoded strings, and we know that the encryption key is composed of two bytes, so we'll use this to forge our attack, we'll take each 16-bytes block of the final hash, try to decrypt it with one of the possible keys, and take the ones that yield a valid hex encoded string, after we got all the encryption keys, we'll re-order the key bytes using the positions in each block by replicating the bytes selection process in the original script. Here's the final script:
```python
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
```
the flag is: `midnight{xwJjPw4Vp0Zl19xIdaNuz6zTeMQ1wlNP}`

it was a pretty easy challenge, but fun nonetheless.

import os
import sys
from binascii import unhexlify
from Crypto.Cipher import AES
from requests import get

if len(sys.argv) < 4:
    print("Usage: python wc24decrypt.py <input file / url> <output file> <key / wc24pubk.mod>")
    sys.exit(1)

if sys.argv[1][:4] == "http":
    with open("temp", "wb") as f:
        f.write(get(sys.argv[1]).content)
        f.close()
    input = open("temp", "rb")
else:
    input = open(sys.argv[1], "rb")

if os.path.exists(sys.argv[3]):
    with open(sys.argv[3], "rb") as f:
        if os.path.getsize(sys.argv[3]) == 16:
            key = f.read()
        elif os.path.getsize(sys.argv[3]) == 544:
            f.seek(512)
            key = f.read(16)
        else:
            print("Error: Input file is not a 16-byte key or a wc24pubk.mod")
            sys.exit(1)
else:
    if len(sys.argv[3]) != 32:
        print("Error: Key is not 16 bytes")
        sys.exit(1)
    key = unhexlify(sys.argv[3])

input.seek(48)
iv = input.read(16)
input.seek(320)
data = input.read()

aes = AES.new(key, AES.MODE_OFB, iv=iv)

with open(sys.argv[2], "wb") as f:
    f.write(aes.decrypt(data))
    f.close()

if os.path.exists("temp"):
    os.remove("temp")

print("Completed Successfully")

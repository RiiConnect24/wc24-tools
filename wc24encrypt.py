import argparse
import os
import rsa
import struct
from binascii import unhexlify
from Crypto.Cipher import AES
from nlzss import encode_file

def u8(data):
    return struct.pack(">B", data)


def u16(data):
    return struct.pack(">H", data)


def u32(data):
    return struct.pack(">I", data)

parser = argparse.ArgumentParser(description="Sign / Encrypt WiiConnect24 files.")
parser.add_argument("-t", "--type",
                        type=str, nargs="+",
                        help="Type of file. Set either enc for encrypted file, or dec for non-encrypted file.")
parser.add_argument("-in", "--input",
                        type=str, nargs="+",
                        help="Input file.")
parser.add_argument("-out", "--output",
                        type=str, nargs="+",
                        help="Output file.")
parser.add_argument("-c", "--compress",
                        type=str, nargs="+",
                        help="If set, this will compress the file before signing with LZ10.")
parser.add_argument("-key", "--aes-key",
                        type=str, nargs="+",
                        help="AES key in hex or a path.")
parser.add_argument("-iv", "--iv-key",
                        type=str, nargs="+",
                        help="AES IV in hex or a path.")
parser.add_argument("-rsa", "--rsa-key-path",
                        type=str, nargs="+",
                        help="RSA private key path. If not specified, it will use the private key in Private.pem if it exists.")

args = parser.parse_args()

if args.compress is not None:
    encode_file(in_path=args.input[0], out_path="temp")
    filename = "temp"
else:
    filename = args.input[0]

with open(filename, "rb") as f:
    data = f.read()

if args.rsa_key_path is not None:
    rsa_key_path = args.rsa_key_path[0]
else:
    rsa_key_path = "Private.pem"

with open(rsa_key_path, "rb") as source_file:
    private_key_data = source_file.read()

private_key = rsa.PrivateKey.load_pkcs1(private_key_data, "PEM")

signature = rsa.sign(data, private_key, "SHA-1")

if args.type[0] == "enc":
    if args.iv_key is not None:
        try:
            iv = unhexlify(args.iv_key[0])
        except:
            iv = open(args.iv_key[0], "rb").read()
    else:
        iv = os.urandom(16)

    try:
        key = unhexlify(args.aes_key[0])
    except:
        key = open(args.aes_key[0], "rb").read()

    aes = AES.new(key, AES.MODE_OFB, iv=iv)
    processed = aes.encrypt(data)
elif args.type[0] == "dec":
    processed = data

content = {"magic": b"WC24" if args.type[0] == "enc" else u32(0)}

content["version"] = u32(1) if args.type[0] == "enc" else u32(0)
content["filler"] = u32(0)
content["crypt_type"] = u8(1) if args.type[0] == "enc" else u8(0)
content["pad"] = u8(0) * 3
content["reserved"] = u8(0) * 32
content["iv"] = iv if args.type[0] == "enc" else u8(0) * 16
content["signature"] = signature
content["data"] = processed

if os.path.exists(args.output[0]):
    os.remove(args.output[0])

if args.type[0] == "dec":
    os.remove("temp")

for values in content.values():
    with open(args.output[0], "ab+") as f:
        f.write(values)

print("Completed Successfully")

# aes_cbc.py -- educational AES-128 ECB block encrypt + CBC wrapper with PKCS#7
from typing import List
import argparse
import os
import sys
import binascii

# AES S-box
s_box = [
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16]

# Round constant
Rcon = [
0x00000000,
0x01000000,0x02000000,0x04000000,0x08000000,0x10000000,0x20000000,0x40000000,0x80000000,0x1b000000,0x36000000
]

def bytes_to_word(b0,b1,b2,b3):
    return (b0<<24)|(b1<<16)|(b2<<8)|b3

def word_to_bytes(word):
    return [(word>>24)&0xff, (word>>16)&0xff, (word>>8)&0xff, word&0xff]

def rot_word(word):
    return ((word<<8)&0xffffffff) | ((word>>24)&0xff)

def sub_word(word):
    b = word_to_bytes(word)
    sb = [s_box[x] for x in b]
    return bytes_to_word(*sb)

def key_expansion(key: bytes) -> List[int]:
    # key: 16 bytes -> 44 words (4*(Nr+1))
    if len(key) != 16:
        raise ValueError("Only AES-128 (16-byte key) supported in this implementation.")
    Nk = 4
    Nr = 10
    w = [0]*(4*(Nr+1))
    # first Nk words from key
    for i in range(Nk):
        w[i] = bytes_to_word(key[4*i], key[4*i+1], key[4*i+2], key[4*i+3])
    for i in range(Nk, 4*(Nr+1)):
        temp = w[i-1]
        if i % Nk == 0:
            temp = sub_word(rot_word(temp)) ^ Rcon[i//Nk]
        w[i] = w[i-Nk] ^ temp
    return w

def add_round_key(state: List[int], round_key_words: List[int]):
    # state is 16-byte list (row-major as bytes)
    key_bytes = []
    for w in round_key_words:
        key_bytes.extend(word_to_bytes(w))
    for i in range(16):
        state[i] ^= key_bytes[i]

def sub_bytes(state: List[int]):
    for i in range(16):
        state[i] = s_box[state[i]]

def shift_rows(state: List[int]):
    # state is column-major internally in AES; but we will treat as 4x4 matrix in row-major to perform shiftrows accordingly
    # Convert to 4x4 matrix (row, col):
    m = [[state[r + 4*c] for c in range(4)] for r in range(4)]
    # shift rows
    for r in range(1,4):
        m[r] = m[r][r:] + m[r][:r]
    # write back
    for r in range(4):
        for c in range(4):
            state[r + 4*c] = m[r][c]

def xtime(a):
    return ((a<<1) ^ 0x1b) & 0xff if (a & 0x80) else (a<<1) & 0xff

def mix_single_column(a):
    # a is 4-byte column
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a0 = a[0] ^ t ^ xtime(a[0] ^ a[1])
    a1 = a[1] ^ t ^ xtime(a[1] ^ a[2])
    a2 = a[2] ^ t ^ xtime(a[2] ^ a[3])
    a3 = a[3] ^ t ^ xtime(a[3] ^ u)
    return [a0 & 0xff, a1 & 0xff, a2 & 0xff, a3 & 0xff]

def mix_columns(state: List[int]):
    # operate on columns
    for c in range(4):
        col = [state[r + 4*c] for r in range(4)]
        mixed = mix_single_column(col)
        for r in range(4):
            state[r + 4*c] = mixed[r]

def encrypt_block(key: bytes, block: bytes) -> bytes:
    if len(block) != 16:
        raise ValueError("Block must be 16 bytes.")
    w = key_expansion(key)
    Nr = 10
    state = list(block)
    # initial AddRoundKey
    add_round_key(state, w[0:4])
    for rnd in range(1, Nr):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, w[4*rnd:4*rnd+4])
    # final round
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, w[4*Nr:4*Nr+4])
    return bytes(state)

# PKCS#7 padding
def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    if block_size <= 0 or block_size > 255:
        raise ValueError("Invalid block size")
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len])*pad_len

def pkcs7_unpad(padded: bytes, block_size: int = 16) -> bytes:
    if not padded or len(padded) % block_size != 0:
        raise ValueError("Invalid padded data length")
    pad_len = padded[-1]
    if pad_len <= 0 or pad_len > block_size:
        raise ValueError("Invalid padding")
    if padded[-pad_len:] != bytes([pad_len])*pad_len:
        raise ValueError("Invalid padding bytes")
    return padded[:-pad_len]

# CBC mode using the encrypt_block function (ECB single-block)
def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("Only 16-byte key supported.")
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes.")
    padded = pkcs7_pad(plaintext, 16)
    blocks = [padded[i:i+16] for i in range(0, len(padded), 16)]
    prev = iv
    ct = bytearray()
    for blk in blocks:
        xored = bytes(a ^ b for a,b in zip(blk, prev))
        enc = encrypt_block(key, xored)
        ct.extend(enc)
        prev = enc
    return bytes(ct)

def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("Only 16-byte key supported.")
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes.")
    if len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext length must be multiple of 16")
    # We need decrypt_block to invert encrypt_block. For compactness, implement a simple decrypt_block here by
    # implementing inverse functions (InvSubBytes, InvShiftRows, InvMixColumns) and key schedule re-use.
    # For brevity in this educational snippet, we'll implement a decryption routine now.

    # Precompute inverse sbox
    inv_sbox = [0]*256
    for i, v in enumerate(s_box):
        inv_sbox[v] = i

    def inv_sub_bytes(state):
        for i in range(16):
            state[i] = inv_sbox[state[i]]

    def inv_shift_rows(state):
        m = [[state[r + 4*c] for c in range(4)] for r in range(4)]
        for r in range(1,4):
            # right rotate by r
            m[r] = m[r][-r:] + m[r][:-r]
        for r in range(4):
            for c in range(4):
                state[r + 4*c] = m[r][c]

    def mul(a, b):
        # multiply a by b in GF(2^8)
        res = 0
        for i in range(8):
            if b & 1:
                res ^= a
            hi = a & 0x80
            a = (a << 1) & 0xff
            if hi:
                a ^= 0x1b
            b >>= 1
        return res

    def inv_mix_single_column(a):
        # a is 4-byte column
        return [
            (mul(a[0],0x0e) ^ mul(a[1],0x0b) ^ mul(a[2],0x0d) ^ mul(a[3],0x09)) & 0xff,
            (mul(a[0],0x09) ^ mul(a[1],0x0e) ^ mul(a[2],0x0b) ^ mul(a[3],0x0d)) & 0xff,
            (mul(a[0],0x0d) ^ mul(a[1],0x09) ^ mul(a[2],0x0e) ^ mul(a[3],0x0b)) & 0xff,
            (mul(a[0],0x0b) ^ mul(a[1],0x0d) ^ mul(a[2],0x09) ^ mul(a[3],0x0e)) & 0xff,
        ]

    def inv_mix_columns(state):
        for c in range(4):
            col = [state[r + 4*c] for r in range(4)]
            mixed = inv_mix_single_column(col)
            for r in range(4):
                state[r + 4*c] = mixed[r]

    # Key schedule
    w = key_expansion(key)
    Nr = 10

    out = bytearray()
    for i in range(0, len(ciphertext), 16):
        block = list(ciphertext[i:i+16])
        # decryption: state = block
        state = block[:]
        # initial round key (last)
        add_round_key(state, w[4*Nr:4*Nr+4])
        # inverse final round
        inv_shift_rows(state)
        inv_sub_bytes(state)
        for rnd in range(Nr-1, 0, -1):
            add_round_key(state, w[4*rnd:4*rnd+4])
            inv_mix_columns(state)
            inv_shift_rows(state)
            inv_sub_bytes(state)
        add_round_key(state, w[0:4])
        # XOR with prev (IV or previous ciphertext)
        prev = iv if i == 0 else ciphertext[i-16:i]
        plain_block = bytes(a ^ b for a,b in zip(state, prev))
        out.extend(plain_block)
    return pkcs7_unpad(bytes(out), 16)


# Example test / usage
def file_encrypt(key_bytes: bytes, in_path: str, out_path: str):
    if len(key_bytes) != 16:
        raise ValueError("Key must be 16 bytes (AES-128)")
    with open(in_path, "rb") as f:
        plaintext = f.read()
    iv = os.urandom(16)
    ct = aes_cbc_encrypt(key_bytes, iv, plaintext)
    # write IV || ciphertext
    with open(out_path, "wb") as f:
        f.write(iv + ct)

def file_decrypt(key_bytes: bytes, in_path: str, out_path: str):
    if len(key_bytes) != 16:
        raise ValueError("Key must be 16 bytes (AES-128)")
    with open(in_path, "rb") as f:
        data = f.read()
    if len(data) < 16:
        raise ValueError("Input too short to contain IV + ciphertext")
    iv = data[:16]
    ct = data[16:]
    pt = aes_cbc_decrypt(key_bytes, iv, ct)
    with open(out_path, "wb") as f:
        f.write(pt)

def parse_key(hex_or_file: str) -> bytes:
    # If value looks like hex (only hex chars, even length), parse as hex; otherwise treat as filename
    s = hex_or_file.strip()
    is_hex = all(c in "0123456789abcdefABCDEF" for c in s) and len(s) % 2 == 0
    if is_hex:
        key = bytes.fromhex(s)
        return key
    # otherwise read key bytes from file
    if not os.path.exists(s):
        raise FileNotFoundError(f"Key file not found: {s}")
    with open(s, "rb") as f:
        key = f.read()
    return key

def run_selftest():
    # NIST AES-128 test vector (single block)
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    pt  = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    expected_ct = "3ad77bb40d7a3660a89ecaf32466ef97"
    ct = encrypt_block(key, pt).hex()
    print("AES-128 ECB encrypt:", ct)
    assert ct == expected_ct, f"ECB vector mismatch: {ct} != {expected_ct}"

    # CBC test: encrypt and decrypt roundtrip
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    msg = b"Hello CBC world! AES from scratch."
    ciphertext = aes_cbc_encrypt(key, iv, msg)
    recovered = aes_cbc_decrypt(key, iv, ciphertext)
    assert recovered == msg
    print("CBC roundtrip OK")

def main(argv=None):
    p = argparse.ArgumentParser(description="AES-128 CBC (educational) file encrypt/decrypt")
    # subcommands are optional so --selftest can be used without specifying a command
    sub = p.add_subparsers(dest="command", required=False)

    enc = sub.add_parser("encrypt", help="Encrypt a file (writes IV||ciphertext)")
    enc.add_argument("--key", required=True, help="Hex key (32 hex chars) or path to key file")
    enc.add_argument("infile", help="Input file to encrypt")
    enc.add_argument("outfile", help="Output file (written) - will contain IV||ciphertext")

    dec = sub.add_parser("decrypt", help="Decrypt a file produced by this tool (expects IV||ciphertext)")
    dec.add_argument("--key", required=True, help="Hex key (32 hex chars) or path to key file")
    dec.add_argument("infile", help="Input file to decrypt (IV||ciphertext)")
    dec.add_argument("outfile", help="Output file for plaintext")

    p.add_argument("--selftest", action="store_true", help="Run built-in self-tests and exit")

    args = p.parse_args(argv)
    if args.selftest:
        run_selftest()
        return 0

    if args.command == "encrypt":
        key = parse_key(args.key)
        file_encrypt(key, args.infile, args.outfile)
        print(f"Encrypted {args.infile} -> {args.outfile} (IV prepended)")
    elif args.command == "decrypt":
        key = parse_key(args.key)
        file_decrypt(key, args.infile, args.outfile)
        print(f"Decrypted {args.infile} -> {args.outfile}")
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as e:
        print("Self-test failed:", e, file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print("Error:", e, file=sys.stderr)
        sys.exit(1)
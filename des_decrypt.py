"""
Our own additions on top of Maam's DES code.
Salman and Asif, Advanced Cryptography I.

des_core.py has encryption only, so the decryption side is written here.
"""

from des_core import *


def des_decrypt_block(block, subkeys):
    """block: 8 bytes, subkeys: from generate_subkeys -> 8 bytes plaintext.
    Same 16 rounds as encryption, only the round keys are fed in backwards."""
    bits = permute(bytes_to_bits(block), IP)     # initial permutation
    L, R = bits[:32], bits[32:]
    for k in reversed(subkeys):                  # 16 rounds, keys reversed
        L, R = R, xor(L, feistel(R, k))
    return bits_to_bytes(permute(R + L, FP))     # swap halves, final permutation


def des_ecb_decrypt(data, key):
    sk = generate_subkeys(key)
    out = bytearray()
    for i in range(0, len(data), 8):
        out += des_decrypt_block(data[i:i+8], sk)
    n = out[-1]                 # pkcs7: last byte says how many to drop
    return bytes(out[:-n])


def des_cfb_decrypt(data, key, iv):
    sk = generate_subkeys(key)
    reg = iv
    out = bytearray()
    for i in range(0, len(data), 8):
        c = data[i:i+8]
        ks = des_encrypt_block(reg, sk)     # CFB only ever needs the forward direction
        out += bytes(x ^ y for x, y in zip(c, ks))
        reg = c                 # feedback is the ciphertext
    return bytes(out)

# Script 01: text encryption, CTR round trip and single block decryption.
from des_core import *
from des_decrypt import des_decrypt_block
import os

key = b"salman12"
nonce = os.urandom(4)
msg = b"Salman and Asif, Advanced Cryptography I"

ct = des_ctr_encrypt(msg, key, nonce)
pt = des_ctr_encrypt(ct, key, nonce)     # CTR decrypts with the same function

print("cipher:", ct.hex())
print("back  :", pt)
print("match :", pt == msg)

sk = generate_subkeys(b"salman12")
block = b"SALMAN12"            # exactly 8 bytes
ct = des_encrypt_block(block, sk)
pt = des_decrypt_block(ct, sk)
print("cipher :", ct.hex())
print("back   :", pt)
print("match  :", pt == block)

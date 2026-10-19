"""
DES core, modes and padding.

This file is Prof. Sadiqa Arshad's code from DES_weak_keys_padding_modes.ipynb,
copied into a plain .py file so it can be run locally and imported.
Nothing here has been changed.
"""

# ---------- STEP 1: DES tables ----------
IP = [58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,
      62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
      57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,
      61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7]

FP = [40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,
      38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,
      36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,
      34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25]

E  = [32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,
      16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1]

P  = [16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,
      2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25]

PC1 = [57,49,41,33,25,17,9,1,58,50,42,34,26,18,
       10,2,59,51,43,35,27,19,11,3,60,52,44,36,
       63,55,47,39,31,23,15,7,62,54,46,38,30,22,
       14,6,61,53,45,37,29,21,13,5,28,20,12,4]

PC2 = [14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,
       41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32]

SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

SBOXES = [
 [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7, 0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
  4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0, 15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
 [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10, 3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
  0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15, 13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
 [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8, 13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
  13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7, 1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
 [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15, 13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
  10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4, 3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
 [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9, 14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
  4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14, 11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
 [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11, 10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
  9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6, 4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
 [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1, 13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
  1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2, 6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
 [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7, 1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
  7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8, 2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11],
]

# ---------- STEP 2: helper functions ----------
def bytes_to_bits(data):
    """bytes -> list of bits (MSB first)"""
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits

def bits_to_bytes(bits):
    """list of bits -> bytes"""
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for b in bits[i:i+8]:
            byte = (byte << 1) | b
        out.append(byte)
    return bytes(out)

def permute(bits, table):
    """Rearrange bits according to a table (tables are 1-indexed)"""
    return [bits[i - 1] for i in table]

def xor(a, b):
    return [x ^ y for x, y in zip(a, b)]

def left_rotate(bits, n):
    return bits[n:] + bits[:n]

# ---------- STEP 3: key schedule (16 round keys) ----------
def generate_subkeys(key):
    """key: 8 bytes -> list of sixteen 48-bit round keys"""
    key_bits = bytes_to_bits(key)
    key56 = permute(key_bits, PC1)          # 64 -> 56 bits
    C, D = key56[:28], key56[28:]
    subkeys = []
    for shift in SHIFTS:
        C = left_rotate(C, shift)
        D = left_rotate(D, shift)
        subkeys.append(permute(C + D, PC2))  # 56 -> 48 bits
    return subkeys

# ---------- STEP 4: S-box substitution ----------
def sbox_substitution(bits48):
    """48 bits -> 32 bits through the 8 S-boxes"""
    out = []
    for i in range(8):
        chunk = bits48[i*6:(i+1)*6]
        row = (chunk[0] << 1) | chunk[5]
        col = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4]
        val = SBOXES[i][row * 16 + col]
        out.extend([(val >> 3) & 1, (val >> 2) & 1, (val >> 1) & 1, val & 1])
    return out

# ---------- STEP 5: Feistel function f(R, K) ----------
def feistel(R, subkey):
    expanded = permute(R, E)                 # 32 -> 48
    mixed = xor(expanded, subkey)            # XOR with round key
    substituted = sbox_substitution(mixed)   # 48 -> 32
    return permute(substituted, P)           # P-box

# ---------- STEP 6: encrypt one 64-bit block ----------
def des_encrypt_block(block, subkeys):
    """block: 8 bytes, subkeys: from generate_subkeys -> 8 bytes ciphertext"""
    bits = permute(bytes_to_bits(block), IP)     # initial permutation
    L, R = bits[:32], bits[32:]
    for k in subkeys:                            # 16 rounds
        L, R = R, xor(L, feistel(R, k))
    return bits_to_bytes(permute(R + L, FP))     # swap halves, final permutation

# ---------- STEP 7: self-test (known test vector) ----------
def des_self_test():
    key = bytes.fromhex("133457799BBCDFF1")
    pt  = bytes.fromhex("0123456789ABCDEF")
    ct  = des_encrypt_block(pt, generate_subkeys(key))
    assert ct.hex().upper() == "85E813540F0AB405", ct.hex()
    print("DES core OK ->", ct.hex().upper())

# STEP W1: the 4 weak keys and the 6 semi-weak key pairs
WEAK_KEYS = [
    "0101010101010101",
    "FEFEFEFEFEFEFEFE",
    "E0E0E0E0F1F1F1F1",
    "1F1F1F1F0E0E0E0E",
]
SEMI_WEAK_PAIRS = [
    ("011F011F010E010E", "1F011F010E010E01"),
    ("01E001E001F101F1", "E001E001F101F101"),
    ("01FE01FE01FE01FE", "FE01FE01FE01FE01"),
    ("1FE01FE00EF10EF1", "E01FE01FF10EF10E"),
    ("1FFE1FFE0EFE0EFE", "FE1FFE1FFE0EFE0E"),
    ("E0FEE0FEF1FEF1FE", "FEE0FEE0FEF1FEF1"),
]

def strip_parity(key):
    """Clear the parity bit (lowest bit) of every key byte"""
    return bytes(b & 0xFE for b in key)

WEAK_SET = {strip_parity(bytes.fromhex(k)) for k in WEAK_KEYS}
SEMI_WEAK_SET = {strip_parity(bytes.fromhex(k)) for pair in SEMI_WEAK_PAIRS for k in pair}

# STEP W2: key classification function
def check_key(key):
    """Returns 'weak', 'semi-weak' or 'ok'"""
    k = strip_parity(key)
    if k in WEAK_SET:      return "weak"
    if k in SEMI_WEAK_SET: return "semi-weak"
    return "ok"

def get_subkeys_checked(key):
    """Generate round keys but warn when the key is weak"""
    status = check_key(key)
    if status != "ok":
        print(f"WARNING: {key.hex().upper()} is a {status} DES key!")
    return generate_subkeys(key)

# STEP P1: four padding schemes (block size = 8)
BLOCK = 8

def pad_zero(data):
    """Zero padding: add 0x00 bytes (ambiguous if the data itself ends in 0x00)"""
    return data + b"\x00" * ((-len(data)) % BLOCK)

def pad_pkcs7(data):
    """PKCS#5/7: add n bytes, each of value n (always adds 1..8 bytes)"""
    n = BLOCK - (len(data) % BLOCK)
    return data + bytes([n]) * n

def pad_iso7816(data):
    """ISO/IEC 7816-4: add 0x80 then 0x00 bytes (always adds 1..8 bytes)"""
    n = BLOCK - (len(data) % BLOCK)
    return data + b"\x80" + b"\x00" * (n - 1)

def pad_ansi_x923(data):
    """ANSI X9.23: add 0x00 bytes, last byte holds the padding length"""
    n = BLOCK - (len(data) % BLOCK)
    return data + b"\x00" * (n - 1) + bytes([n])

PADDING = {"zero": pad_zero, "pkcs7": pad_pkcs7, "iso7816": pad_iso7816, "x923": pad_ansi_x923}

# STEP M1: helper
def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

# STEP M2: ECB mode
def des_ecb_encrypt(data, key, padding="pkcs7"):
    subkeys = get_subkeys_checked(key)
    data = PADDING[padding](data)                  # padding is required in ECB
    out = bytearray()
    for i in range(0, len(data), 8):
        out += des_encrypt_block(data[i:i+8], subkeys)   # each block independent
    return bytes(out)

# STEP M3: CTR mode
def des_ctr_encrypt(data, key, nonce):
    """nonce: 4 bytes. Counter block = nonce (4 bytes) || counter (4 bytes)"""
    assert len(nonce) == 4, "nonce must be 4 bytes"
    subkeys = get_subkeys_checked(key)
    out = bytearray()
    for i in range(0, len(data), 8):
        counter_block = nonce + (i // 8).to_bytes(4, "big")
        keystream = des_encrypt_block(counter_block, subkeys)   # encrypt the counter
        chunk = data[i:i+8]                                      # last chunk may be shorter
        out += xor_bytes(chunk, keystream)                       # no padding needed
    return bytes(out)

# STEP M4: CFB mode (full 64-bit feedback)
def des_cfb_encrypt(data, key, iv):
    """iv: 8 bytes"""
    assert len(iv) == 8, "IV must be 8 bytes"
    subkeys = get_subkeys_checked(key)
    register = iv
    out = bytearray()
    for i in range(0, len(data), 8):
        keystream = des_encrypt_block(register, subkeys)   # encrypt previous ciphertext (or IV)
        chunk = data[i:i+8]
        c = xor_bytes(chunk, keystream)
        out += c
        register = c                                       # feedback: ciphertext goes back in
    return bytes(out)

if __name__ == "__main__":
    des_self_test()

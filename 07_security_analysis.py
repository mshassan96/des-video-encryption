# Script 07: security analysis. Histogram, entropy, correlation, key sensitivity.
# Salman and Asif, Advanced Cryptography I.

import os as _os
for _d in ("output/images", "output/video", "output/audio", "output/cipher"):
    _os.makedirs(_d, exist_ok=True)

import os
import numpy as np, cv2
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from des_core import des_ecb_encrypt, des_ctr_encrypt, des_cfb_encrypt

KEY = b"salman12"
SIZE = 256
NONCE, IV = os.urandom(4), os.urandom(8)


def entropy(data):
    """Shannon entropy in bits per byte. 8.0 = perfectly uniform."""
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    p = counts[counts > 0] / len(data)
    return float(-(p * np.log2(p)).sum())


def correlation(img, direction):
    """How strongly a pixel predicts its neighbour. ~1 = normal image, ~0 = noise."""
    if direction == "horizontal":
        a, b = img[:, :-1].ravel(), img[:, 1:].ravel()
    elif direction == "vertical":
        a, b = img[:-1, :].ravel(), img[1:, :].ravel()
    else:
        a, b = img[:-1, :-1].ravel(), img[1:, 1:].ravel()
    return float(np.corrcoef(a.astype(float), b.astype(float))[0, 1])


def npcr_uaci(c1, c2):
    """NPCR: % of bytes that differ. UACI: average difference, as a %."""
    a = np.frombuffer(c1, dtype=np.uint8).astype(int)
    b = np.frombuffer(c2[:len(c1)], dtype=np.uint8).astype(int)
    npcr = (a != b).mean() * 100
    uaci = (np.abs(a - b) / 255).mean() * 100
    return npcr, uaci


def as_img(data):
    return np.frombuffer(data[:SIZE*SIZE], dtype=np.uint8).reshape(SIZE, SIZE)


img = cv2.resize(cv2.imread("input/lenna.png", cv2.IMREAD_GRAYSCALE), (SIZE, SIZE))
plain = img.tobytes()

ciphers = {
    "Plain": plain,
    "ECB":   des_ecb_encrypt(plain, KEY),
    "CTR":   des_ctr_encrypt(plain, KEY, NONCE),
    "CFB":   des_cfb_encrypt(plain, KEY, IV),
}

# ---------- entropy and correlation ----------
print("%-7s %10s %12s %12s %12s" % ("", "entropy", "horizontal", "vertical", "diagonal"))
for name, data in ciphers.items():
    e = entropy(data)
    pic = as_img(data)
    print("%-7s %10.4f %12.4f %12.4f %12.4f" % (
        name, e, correlation(pic, "horizontal"),
        correlation(pic, "vertical"), correlation(pic, "diagonal")))

# ---------- histograms ----------
fig, ax = plt.subplots(1, 4, figsize=(16, 3.5))
for i, (name, data) in enumerate(ciphers.items()):
    ax[i].hist(np.frombuffer(data, dtype=np.uint8), bins=256, range=(0, 255),
               color="steelblue" if name == "Plain" else "indianred")
    ax[i].set_title(f"{name}  (entropy {entropy(data):.3f})")
    ax[i].set_xlabel("Pixel value")
ax[0].set_ylabel("Count")
plt.tight_layout()
plt.savefig("output/images/histograms.png", dpi=110)
print("\nsaved output/images/histograms.png")

# ---------- key sensitivity ----------
print("\n--- key sensitivity (ECB) ---")
base = ciphers["ECB"]

parity_key = bytes([KEY[0] ^ 0x01]) + KEY[1:]        # flips a PARITY bit
real_key   = bytes([KEY[0] ^ 0x02]) + KEY[1:]        # flips a REAL key bit

n, u = npcr_uaci(base, des_ecb_encrypt(plain, parity_key))
print(f"  key {KEY} vs {parity_key} (parity bit): NPCR {n:6.2f}%  UACI {u:5.2f}%")
n, u = npcr_uaci(base, des_ecb_encrypt(plain, real_key))
print(f"  key {KEY} vs {real_key} (real bit)  : NPCR {n:6.2f}%  UACI {u:5.2f}%")

# ---------- plaintext sensitivity ----------
print("\n--- plaintext sensitivity: flip one bit of the image ---")
tweaked = bytearray(plain)
tweaked[0] ^= 0x01
tweaked = bytes(tweaked)
for mode, fn in [("ECB", lambda d: des_ecb_encrypt(d, KEY)),
                 ("CTR", lambda d: des_ctr_encrypt(d, KEY, NONCE)),
                 ("CFB", lambda d: des_cfb_encrypt(d, KEY, IV))]:
    n, u = npcr_uaci(ciphers[mode], fn(tweaked))
    print(f"  {mode}: NPCR {n:6.3f}%  UACI {u:5.3f}%")

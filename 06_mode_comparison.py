# Script 06: compare ECB, CTR and CFB on images and on video frames.
# Salman and Asif, Advanced Cryptography I.

import os as _os
for _d in ("output/images", "output/video", "output/audio", "output/cipher"):
    _os.makedirs(_d, exist_ok=True)

import os, time
import numpy as np, cv2
import matplotlib
matplotlib.use("Agg")                 # no window, just save the figure
import matplotlib.pyplot as plt

from des_core import des_ecb_encrypt, des_ctr_encrypt, des_cfb_encrypt
from des_decrypt import des_ecb_decrypt, des_cfb_decrypt

KEY = b"salman12"
SIZE = 256


def make_flat_image():
    """Big solid areas. ECB only leaks when blocks repeat, and flat regions repeat a lot."""
    img = np.full((SIZE, SIZE), 30, np.uint8)          # dark background
    cv2.rectangle(img, (0, 0), (SIZE, 60), 200, -1)    # light bar on top
    cv2.putText(img, "SALMAN", (18, 120), cv2.FONT_HERSHEY_SIMPLEX, 1.4, 255, 12)
    cv2.putText(img, "ASIF",   (18, 200), cv2.FONT_HERSHEY_SIMPLEX, 1.4, 255, 12)
    return img


def encrypt_all(data):
    """Returns {mode: (ciphertext, encrypt_seconds, decrypt_seconds, round_trip_ok)}"""
    nonce, iv = os.urandom(4), os.urandom(8)
    out = {}

    t = time.perf_counter(); c = des_ecb_encrypt(data, KEY); te = time.perf_counter() - t
    t = time.perf_counter(); p = des_ecb_decrypt(c, KEY);    td = time.perf_counter() - t
    out["ECB"] = (c, te, td, p == data)

    t = time.perf_counter(); c = des_ctr_encrypt(data, KEY, nonce); te = time.perf_counter() - t
    t = time.perf_counter(); p = des_ctr_encrypt(c, KEY, nonce);    td = time.perf_counter() - t
    out["CTR"] = (c, te, td, p == data)

    t = time.perf_counter(); c = des_cfb_encrypt(data, KEY, iv); te = time.perf_counter() - t
    t = time.perf_counter(); p = des_cfb_decrypt(c, KEY, iv);    td = time.perf_counter() - t
    out["CFB"] = (c, te, td, p == data)
    return out


def repeated_blocks(data):
    """How many 8-byte blocks are duplicates. High = patterns survived."""
    blocks = [data[i:i+8] for i in range(0, len(data) - len(data) % 8, 8)]
    return len(blocks) - len(set(blocks)), len(blocks)


# ---------------- images ----------------
flat = make_flat_image()
lenna = cv2.resize(cv2.imread("input/lenna.png", cv2.IMREAD_GRAYSCALE), (SIZE, SIZE))
cv2.imwrite("output/images/flat_image_plain.png", flat)

fig, ax = plt.subplots(2, 4, figsize=(13, 7))
for row, (name, img) in enumerate([("Flat", flat), ("Lenna", lenna)]):
    data = img.tobytes()
    res = encrypt_all(data)
    dup, total = repeated_blocks(data)
    print(f"\n--- {name} ({len(data)} bytes) ---")
    print(f"  plaintext repeated blocks: {dup}/{total}")
    ax[row][0].imshow(img, cmap="gray"); ax[row][0].set_title(f"{name}: original")
    for col, mode in enumerate(["ECB", "CTR", "CFB"], start=1):
        c, te, td, ok = res[mode]
        dup, total = repeated_blocks(c)
        print(f"  {mode}: {len(c)} bytes, enc {te:.1f}s, dec {td:.1f}s, "
              f"round trip {ok}, repeated blocks {dup}/{total}")
        pic = np.frombuffer(c[:SIZE*SIZE], dtype=np.uint8).reshape(SIZE, SIZE)
        ax[row][col].imshow(pic, cmap="gray")
        ax[row][col].set_title(f"{name}: {mode}")
        cv2.imwrite(f"output/images/{name.lower()}_{mode}.png", pic)
for a in ax.ravel():
    a.axis("off")
plt.tight_layout()
plt.savefig("output/images/mode_comparison.png", dpi=110)
print("\nsaved output/images/mode_comparison.png")

# ---------------- video frames ----------------
W, H, N = 160, 120, 10
cap = cv2.VideoCapture("input/sample.mp4")
frames = []
while len(frames) < N:
    ok, f = cap.read()
    if not ok:
        break
    frames.append(cv2.resize(f, (W, H)))
cap.release()
vdata = b"".join(f.tobytes() for f in frames)

print(f"\n--- video, {len(frames)} frames at {W}x{H} ({len(vdata)} bytes) ---")
dup, total = repeated_blocks(vdata)
print(f"  plaintext repeated blocks: {dup}/{total}")
for mode, (c, te, td, ok) in encrypt_all(vdata).items():
    dup, total = repeated_blocks(c)
    print(f"  {mode}: {len(c)} bytes, enc {te:.1f}s, dec {td:.1f}s, "
          f"round trip {ok}, repeated blocks {dup}/{total}")
    cv2.imwrite(f"output/images/videoframe_{mode}.png",
                np.frombuffer(c[:H*W*3], dtype=np.uint8).reshape(H, W, 3))

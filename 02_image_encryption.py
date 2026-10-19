
import os as _os
for _d in ("output/images", "output/video", "output/audio", "output/cipher"):
    _os.makedirs(_d, exist_ok=True)

import numpy as np
import cv2
from des_core import des_ctr_encrypt
import os

img = cv2.imread("input/lenna.png", cv2.IMREAD_GRAYSCALE)
img = cv2.resize(img, (256, 256))
print("shape:", img.shape)

data = img.tobytes()
print("bytes:", len(data))

nonce = os.urandom(4)          # change your existing line to this


ct = des_ctr_encrypt(data, b"salman12", nonce)
enc = np.frombuffer(ct, dtype=np.uint8).reshape(256, 256)

cv2.imwrite("output/images/lenna_encrypted.png", enc)
print("saved output/images/lenna_encrypted.png")

# decrypt
back = des_ctr_encrypt(ct, b"salman12", nonce)
dec = np.frombuffer(back, dtype=np.uint8).reshape(256, 256)
cv2.imwrite("output/images/lenna_decrypted.png", dec)
print("match:", back == data)
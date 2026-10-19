
import os as _os
for _d in ("output/images", "output/video", "output/audio", "output/cipher"):
    _os.makedirs(_d, exist_ok=True)

import numpy as np, cv2, os
from des_core import des_ctr_encrypt

W, H, N = 96, 72, 15        # small while testing

cap = cv2.VideoCapture("input/sample.mp4")
frames = []
while len(frames) < N:
    ok, f = cap.read()
    if not ok: break
    frames.append(cv2.resize(f, (W, H)))
cap.release()
print("frames:", len(frames), "each", frames[0].shape)

# join every frame into ONE long byte string
data = b"".join(f.tobytes() for f in frames)
print("total bytes:", len(data))

key, nonce = b"salman12", os.urandom(4)
ct = des_ctr_encrypt(data, key, nonce)
back = des_ctr_encrypt(ct, key, nonce)
print("match:", back == data)

# save frame 0, before and after
size = H * W * 3
cv2.imwrite("output/images/frame0_small_plain.png", frames[0])
cv2.imwrite("output/images/frame0_small_encrypted.png", np.frombuffer(ct[:size], dtype=np.uint8).reshape(H, W, 3))

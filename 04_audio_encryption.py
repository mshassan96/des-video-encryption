
import os as _os
for _d in ("output/images", "output/video", "output/audio", "output/cipher"):
    _os.makedirs(_d, exist_ok=True)

import subprocess, wave, os
import imageio_ffmpeg
from des_core import des_ctr_encrypt

ffmpeg = imageio_ffmpeg.get_ffmpeg_exe()
src = "input/sample.mp4"

# 1. pull the audio out of the video as a plain WAV (first 3 seconds)
subprocess.run([ffmpeg, "-y", "-hide_banner", "-loglevel", "error",
                "-i", src, "-vn", "-t", "3",
                "-acodec", "pcm_s16le", "output/audio/audio_demo_plain.wav"], check=True)

# 2. read the raw sound samples out of the WAV
with wave.open("output/audio/audio_demo_plain.wav", "rb") as w:
    params = w.getparams()
    samples = w.readframes(w.getnframes())
print("audio bytes:", len(samples))

# 3. encrypt them
key, nonce = b"asif1234", os.urandom(4)
ct = des_ctr_encrypt(samples, key, nonce)
with wave.open("output/audio/audio_demo_encrypted.wav", "wb") as w:
    w.setparams(params)
    w.writeframes(ct)

# 4. decrypt them
back = des_ctr_encrypt(ct, key, nonce)
with wave.open("output/audio/audio_demo_decrypted.wav", "wb") as w:
    w.setparams(params)
    w.writeframes(back)

print("match:", back == samples)

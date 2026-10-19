# Script 05: full pipeline on ANY video. Encrypts the frames AND the audio,
# builds a playable "encrypted" preview, then decrypts everything back.
# Salman and Asif, Advanced Cryptography I.
#
# Usage:
#   python 05_full_pipeline.py                          uses the default clip below
#   python 05_full_pipeline.py "myvideo.mp4"            any video you like
#   python 05_full_pipeline.py "myvideo.mp4" 20         only 20 frames
#   python 05_full_pipeline.py "myvideo.mp4" 20 320 240 20 frames at 320x240 (slower!)
#
# Pure-python DES runs at about 33 KB/s, so frames x width x height x 3
# divided by 33000 is roughly the seconds it will take, twice over.

import os as _os
for _d in ("output/images", "output/video", "output/audio", "output/cipher"):
    _os.makedirs(_d, exist_ok=True)

import os, sys, time, wave, subprocess
import numpy as np, cv2, imageio_ffmpeg
from des_core import des_ctr_encrypt

SRC = sys.argv[1] if len(sys.argv) > 1 else "input/sample.mp4"
N   = int(sys.argv[2]) if len(sys.argv) > 2 else 30
W   = int(sys.argv[3]) if len(sys.argv) > 3 else 160
H   = int(sys.argv[4]) if len(sys.argv) > 4 else 120

KEY = b"asif1234"
FFMPEG = imageio_ffmpeg.get_ffmpeg_exe()

if not os.path.exists(SRC):
    sys.exit(f"Video not found: {SRC}")


def run(args):
    subprocess.run([FFMPEG, "-y", "-hide_banner", "-loglevel", "error"] + args, check=True)


def has_audio(path):
    out = subprocess.run([FFMPEG, "-hide_banner", "-i", path],
                         capture_output=True, text=True).stderr
    return "Audio:" in out


def write_video(path, frames, fps):
    out = cv2.VideoWriter(path, cv2.VideoWriter_fourcc(*"mp4v"), fps, (W, H))
    for f in frames:
        out.write(f)
    out.release()


def write_wav(path, params, data):
    with wave.open(path, "wb") as w:
        w.setparams(params)
        w.writeframes(data)


def to_frames(raw):
    """one long byte string -> list of frames"""
    size = H * W * 3
    return [np.frombuffer(raw[i:i+size], dtype=np.uint8).reshape(H, W, 3)
            for i in range(0, len(raw), size)]


# ---------- 1. read the video frames ----------
cap = cv2.VideoCapture(SRC)
if not cap.isOpened():
    sys.exit(f"OpenCV could not open: {SRC}")
fps = cap.get(cv2.CAP_PROP_FPS) or 25.0
frames = []
while len(frames) < N:
    ok, f = cap.read()
    if not ok:
        break
    frames.append(cv2.resize(f, (W, H)))
cap.release()
if not frames:
    sys.exit("No frames could be read from that file.")
seconds = len(frames) / fps
print(f"source : {SRC}")
print(f"frames : {len(frames)} at {W}x{H}, {fps:.2f} fps = {seconds:.2f} s")

# ---------- 2. pull out the matching slice of audio ----------
audio, aparams = b"", None
if has_audio(SRC):
    run(["-i", SRC, "-vn", "-t", f"{seconds:.3f}", "-ac", "1",
         "-acodec", "pcm_s16le", f"output/audio/audio_plain.wav"])
    with wave.open(f"output/audio/audio_plain.wav", "rb") as w:
        aparams = w.getparams()
        audio = w.readframes(w.getnframes())
else:
    print("note   : this file has no audio track, doing video only")

video_bytes = b"".join(f.tobytes() for f in frames)
print(f"video  : {len(video_bytes)} bytes   audio: {len(audio)} bytes")
print(f"estimate: about {2 * (len(video_bytes) + len(audio)) / 33000:.0f} s total\n")

# ---------- 3. encrypt both, separate nonces ----------
vnonce, anonce = os.urandom(4), os.urandom(4)

t = time.perf_counter()
cipher_video = des_ctr_encrypt(video_bytes, KEY, vnonce)
tv = time.perf_counter() - t
print(f"encrypted video in {tv:.1f}s ({len(video_bytes)/tv/1024:.1f} KB/s)")

cipher_audio = b""
if audio:
    t = time.perf_counter()
    cipher_audio = des_ctr_encrypt(audio, KEY, anonce)
    ta = time.perf_counter() - t
    print(f"encrypted audio in {ta:.1f}s ({len(audio)/ta/1024:.1f} KB/s)")

# the real ciphertext, kept as raw bytes
open(f"output/cipher/cipher_video.bin", "wb").write(cipher_video)
if cipher_audio:
    open(f"output/cipher/cipher_audio.bin", "wb").write(cipher_audio)

# ---------- 4. build the playable encrypted preview ----------
write_video("tmp_enc.mp4", to_frames(cipher_video), fps)
if cipher_audio:
    write_wav(f"output/audio/audio_encrypted.wav", aparams, cipher_audio)
    run(["-i", "tmp_enc.mp4", "-i", f"output/audio/audio_encrypted.wav",
         "-c:v", "copy", "-c:a", "aac", "-shortest", f"output/video/encrypted_preview.mp4"])
else:
    run(["-i", "tmp_enc.mp4", "-c:v", "copy", f"output/video/encrypted_preview.mp4"])

# ---------- 5. decrypt from the raw ciphertext ----------
plain_video = des_ctr_encrypt(cipher_video, KEY, vnonce)
plain_audio = des_ctr_encrypt(cipher_audio, KEY, anonce) if cipher_audio else b""

write_video("tmp_dec.mp4", to_frames(plain_video), fps)
if plain_audio:
    write_wav(f"output/audio/audio_decrypted.wav", aparams, plain_audio)
    run(["-i", "tmp_dec.mp4", "-i", f"output/audio/audio_decrypted.wav",
         "-c:v", "copy", "-c:a", "aac", "-shortest", f"output/video/decrypted.mp4"])
else:
    run(["-i", "tmp_dec.mp4", "-c:v", "copy", f"output/video/decrypted.mp4"])

# the original at the same size, for side by side comparison
write_video("tmp_org.mp4", frames, fps)
if audio:
    run(["-i", "tmp_org.mp4", "-i", f"output/audio/audio_plain.wav",
         "-c:v", "copy", "-c:a", "aac", "-shortest", f"output/video/original.mp4"])
else:
    run(["-i", "tmp_org.mp4", "-c:v", "copy", f"output/video/original.mp4"])

for f in ["tmp_enc.mp4", "tmp_dec.mp4", "tmp_org.mp4"]:
    os.remove(f)

# ---------- 6. proof ----------
cv2.imwrite(f"output/images/frame0_plain.png", frames[0])
cv2.imwrite(f"output/images/frame0_encrypted.png", to_frames(cipher_video)[0])
cv2.imwrite(f"output/images/frame0_decrypted.png", to_frames(plain_video)[0])

print()
print("video round trip:", plain_video == video_bytes)
if audio:
    print("audio round trip:", plain_audio == audio)
print(f"\nwatch output/video/encrypted_preview.mp4 and output/video/decrypted.mp4")

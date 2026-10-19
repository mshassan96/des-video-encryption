"""
Reusable DES media pipeline, used by app.py.

The mode functions here do the same job as the ones in des_core.py and
des_decrypt.py. They are rewritten as explicit loops only so they can report
progress back to the user interface, because a pure python DES takes close to a
minute on even a short clip and a UI with no progress bar looks broken.
"""

import os
import subprocess
import time
import wave

import cv2
import imageio_ffmpeg
import numpy as np

from des_core import des_encrypt_block, generate_subkeys
from des_decrypt import des_decrypt_block

FFMPEG = imageio_ffmpeg.get_ffmpeg_exe()
BLOCK = 8
REPORT_EVERY = 500          # blocks between progress callbacks


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def _loop(data, step, progress, label):
    """Walk the data one block at a time, calling progress now and then."""
    out = bytearray()
    total = max(1, (len(data) + BLOCK - 1) // BLOCK)
    for n, i in enumerate(range(0, len(data), BLOCK)):
        out += step(data[i:i + BLOCK], n)
        if progress and n % REPORT_EVERY == 0:
            progress(n / total, label)
    return bytes(out)


# ---------------------------------------------------------------- CTR
def ctr(data, key, nonce, progress=None, label="CTR"):
    """Encrypts AND decrypts: XOR twice with the same keystream returns the input."""
    sk = generate_subkeys(key)

    def step(chunk, n):
        keystream = des_encrypt_block(nonce + n.to_bytes(4, "big"), sk)
        return _xor(chunk, keystream)

    return _loop(data, step, progress, label)


# ---------------------------------------------------------------- ECB
def ecb_encrypt(data, key, progress=None, label="ECB"):
    sk = generate_subkeys(key)
    pad = BLOCK - (len(data) % BLOCK)           # pkcs7, always adds 1 to 8 bytes
    data = data + bytes([pad]) * pad
    return _loop(data, lambda c, n: des_encrypt_block(c, sk), progress, label)


def ecb_decrypt(data, key, progress=None, label="ECB"):
    sk = generate_subkeys(key)
    out = _loop(data, lambda c, n: des_decrypt_block(c, sk), progress, label)
    return out[:-out[-1]]                       # strip the padding


# ---------------------------------------------------------------- CFB
def cfb_encrypt(data, key, iv, progress=None, label="CFB"):
    sk = generate_subkeys(key)
    reg = [iv]                                  # list so the closure can reassign

    def step(chunk, n):
        c = _xor(chunk, des_encrypt_block(reg[0], sk))
        reg[0] = c
        return c

    return _loop(data, step, progress, label)


def cfb_decrypt(data, key, iv, progress=None, label="CFB"):
    sk = generate_subkeys(key)
    reg = [iv]

    def step(chunk, n):
        p = _xor(chunk, des_encrypt_block(reg[0], sk))
        reg[0] = chunk                          # feedback is the ciphertext
        return p

    return _loop(data, step, progress, label)


# ---------------------------------------------------------------- helpers
def estimate_seconds(nbytes, rate=33000):
    """Rough wall clock for one direction, at the measured 33 KB/s."""
    return nbytes / rate


def has_audio(path):
    out = subprocess.run([FFMPEG, "-hide_banner", "-i", path],
                         capture_output=True, text=True).stderr
    return "Audio:" in out


def _ffmpeg(args):
    subprocess.run([FFMPEG, "-y", "-hide_banner", "-loglevel", "error"] + args, check=True)


def _write_playable(path, frames, fps, w, h, wav=None):
    """cv2 writes MPEG-4 part 2, which browsers refuse to play, so re-encode to H.264."""
    tmp = path + ".tmp.mp4"
    writer = cv2.VideoWriter(tmp, cv2.VideoWriter_fourcc(*"mp4v"), fps, (w, h))
    for f in frames:
        writer.write(f)
    writer.release()
    args = ["-i", tmp]
    if wav:
        args += ["-i", wav]
    args += ["-c:v", "libx264", "-pix_fmt", "yuv420p", "-preset", "veryfast"]
    if wav:
        args += ["-c:a", "aac", "-shortest"]
    _ffmpeg(args + [path])
    os.remove(tmp)


def _to_frames(raw, w, h):
    size = h * w * 3
    return [np.frombuffer(raw[i:i + size], dtype=np.uint8).reshape(h, w, 3)
            for i in range(0, len(raw), size)]


# ---------------------------------------------------------------- the pipeline
def encrypt_media(video_path, outdir, frames=30, w=160, h=120,
                  key=b"salman12", mode="CTR", progress=None):
    """Encrypt the frames and the audio of one clip, then decrypt both back.

    Returns a dict of output paths, timings and verification results.
    """
    os.makedirs(outdir, exist_ok=True)
    w, h = w - (w % 2), h - (h % 2)             # H.264 needs even dimensions

    def note(frac, label):
        if progress:
            progress(min(max(frac, 0.0), 1.0), label)

    # 1. frames
    note(0.0, "Reading frames")
    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        raise RuntimeError(f"Could not open {video_path}")
    fps = cap.get(cv2.CAP_PROP_FPS) or 25.0
    picked = []
    while len(picked) < frames:
        ok, f = cap.read()
        if not ok:
            break
        picked.append(cv2.resize(f, (w, h)))
    cap.release()
    if not picked:
        raise RuntimeError("No frames could be read from that file")
    seconds = len(picked) / fps
    video_bytes = b"".join(f.tobytes() for f in picked)

    # 2. audio
    note(0.03, "Extracting audio")
    audio, aparams = b"", None
    wav_plain = os.path.join(outdir, "audio_plain.wav")
    if has_audio(video_path):
        _ffmpeg(["-i", video_path, "-vn", "-t", f"{seconds:.3f}", "-ac", "1",
                 "-acodec", "pcm_s16le", wav_plain])
        with wave.open(wav_plain, "rb") as wv:
            aparams = wv.getparams()
            audio = wv.readframes(wv.getnframes())

    nonce, iv = os.urandom(4), os.urandom(8)

    def enc(data, lab, lo, hi):
        def p(f, _l):
            note(lo + (hi - lo) * f, lab)
        if mode == "CTR":
            return ctr(data, key, nonce, p)
        if mode == "ECB":
            return ecb_encrypt(data, key, p)
        return cfb_encrypt(data, key, iv, p)

    def dec(data, lab, lo, hi):
        def p(f, _l):
            note(lo + (hi - lo) * f, lab)
        if mode == "CTR":
            return ctr(data, key, nonce, p)
        if mode == "ECB":
            return ecb_decrypt(data, key, p)
        return cfb_decrypt(data, key, iv, p)

    # 3. encrypt
    t0 = time.perf_counter()
    cipher_video = enc(video_bytes, f"Encrypting video ({mode})", 0.05, 0.45)
    cipher_audio = enc(audio, f"Encrypting audio ({mode})", 0.45, 0.50) if audio else b""
    enc_time = time.perf_counter() - t0

    with open(os.path.join(outdir, "cipher_video.bin"), "wb") as fh:
        fh.write(cipher_video)
    if cipher_audio:
        with open(os.path.join(outdir, "cipher_audio.bin"), "wb") as fh:
            fh.write(cipher_audio)

    # 4. decrypt
    t0 = time.perf_counter()
    plain_video = dec(cipher_video, f"Decrypting video ({mode})", 0.50, 0.90)
    plain_audio = dec(cipher_audio, f"Decrypting audio ({mode})", 0.90, 0.95) if cipher_audio else b""
    dec_time = time.perf_counter() - t0

    # ECB pads, so the ciphertext holds one extra block. Trim it for display.
    display_cipher = cipher_video[:len(video_bytes)]

    # 5. write the playable files
    note(0.95, "Writing video files")
    wav_enc = wav_dec = None
    if cipher_audio:
        wav_enc = os.path.join(outdir, "audio_encrypted.wav")
        wav_dec = os.path.join(outdir, "audio_decrypted.wav")
        for path, payload in [(wav_enc, cipher_audio[:len(audio)]), (wav_dec, plain_audio)]:
            with wave.open(path, "wb") as wv:
                wv.setparams(aparams)
                wv.writeframes(payload)

    paths = {
        "original":  os.path.join(outdir, "original.mp4"),
        "encrypted": os.path.join(outdir, "encrypted_preview.mp4"),
        "decrypted": os.path.join(outdir, "decrypted.mp4"),
    }
    _write_playable(paths["original"], picked, fps, w, h, wav_plain if audio else None)
    _write_playable(paths["encrypted"], _to_frames(display_cipher, w, h), fps, w, h, wav_enc)
    _write_playable(paths["decrypted"], _to_frames(plain_video, w, h), fps, w, h, wav_dec)

    note(1.0, "Done")
    return {
        "paths": paths,
        "frame_plain": picked[0],
        "frame_encrypted": _to_frames(display_cipher, w, h)[0],
        "frame_decrypted": _to_frames(plain_video, w, h)[0],
        "video_ok": plain_video == video_bytes,
        "audio_ok": (plain_audio == audio) if audio else None,
        "video_bytes": len(video_bytes),
        "audio_bytes": len(audio),
        "frames": len(picked),
        "fps": fps,
        "seconds": seconds,
        "enc_time": enc_time,
        "dec_time": dec_time,
        "throughput": (len(video_bytes) + len(audio)) / enc_time / 1024,
        "mode": mode,
    }

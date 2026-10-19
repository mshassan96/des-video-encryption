"""
DES video and audio encryption, with a browser interface.
Advanced Cryptography I.

Run it with:    python -m streamlit run app.py
"""

import os
import tempfile

import streamlit as st

from des_core import check_key
from des_pipeline import encrypt_media, estimate_seconds

SAMPLE = os.path.join("input", "sample.mp4")
OUTDIR = os.path.join("output", "ui")

st.set_page_config(page_title="DES Video Encryption", page_icon="*", layout="wide")
st.title("DES Video and Audio Encryption")
st.caption("Encrypts the picture and the sound of a clip with DES, then decrypts both back.")

# ------------------------------------------------------------------ controls
with st.sidebar:
    st.header("Settings")

    mode = st.selectbox("Mode of operation", ["CTR", "CFB", "ECB"],
                        help="CTR is the practical choice for video. ECB leaks patterns.")
    key_text = st.text_input("Key (exactly 8 characters)", "salman12", max_chars=8)

    st.divider()
    frames = st.slider("Frames", 5, 60, 20,
                       help="More frames means a longer video and a longer wait.")
    size = st.select_slider("Frame size", ["64x48", "96x72", "128x96", "160x120", "240x180"],
                            value="96x72")
    w, h = (int(v) for v in size.split("x"))

    st.divider()
    st.caption("This DES runs at about 33 KB/s, so keep the numbers small.")

# key validation
key = key_text.encode()
if len(key) != 8:
    st.sidebar.error(f"Key must be exactly 8 characters, yours is {len(key)}.")
    st.stop()

status = check_key(key)
if status != "ok":
    st.sidebar.warning(f"That is a {status} DES key. It will still run, but it is insecure.")
else:
    st.sidebar.success("Key is not weak or semi-weak.")

# ------------------------------------------------------------------ the video
st.subheader("1. Choose a video")
uploaded = st.file_uploader("Upload any video file", type=["mp4", "avi", "mov", "mkv", "webm"])

if uploaded:
    tmp = os.path.join(tempfile.gettempdir(), uploaded.name)
    with open(tmp, "wb") as fh:
        fh.write(uploaded.getbuffer())
    video_path = tmp
    st.success(f"Using your upload: {uploaded.name}")
elif os.path.exists(SAMPLE):
    video_path = SAMPLE
    st.info("No upload, so the included sample clip will be used.")
else:
    st.error("No video uploaded and no sample found at input/sample.mp4")
    st.stop()

# ------------------------------------------------------------------ estimate
payload = frames * w * h * 3
est = estimate_seconds(payload) * 2          # encrypt and decrypt

st.subheader("2. Run it")
c1, c2, c3 = st.columns(3)
c1.metric("Data to process", f"{payload / 1024:.0f} KB")
c2.metric("Estimated time", f"{est:.0f} s")
c3.metric("Mode", mode)

if est > 180:
    st.warning("That will take over three minutes. Consider fewer frames or a smaller size.")

if st.button("Encrypt and decrypt", type="primary"):
    bar = st.progress(0.0, text="Starting")

    def on_progress(fraction, label):
        bar.progress(fraction, text=f"{label}  ({fraction * 100:.0f}%)")

    try:
        result = encrypt_media(video_path, OUTDIR, frames=frames, w=w, h=h,
                               key=key, mode=mode, progress=on_progress)
    except Exception as exc:                 # noqa: BLE001
        bar.empty()
        st.error(f"Something went wrong: {exc}")
        st.stop()

    bar.empty()
    st.session_state["result"] = result

# ------------------------------------------------------------------ results
result = st.session_state.get("result")
if result:
    st.divider()
    st.subheader("3. Results")

    ok = result["video_ok"] and (result["audio_ok"] is not False)
    if ok:
        st.success("Decrypted output matches the original byte for byte, "
                   "for both the picture and the sound.")
    else:
        st.error("The round trip did not match. Something is wrong.")

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Frames", result["frames"])
    m2.metric("Encrypt", f"{result['enc_time']:.1f} s")
    m3.metric("Decrypt", f"{result['dec_time']:.1f} s")
    m4.metric("Throughput", f"{result['throughput']:.1f} KB/s")

    st.markdown("**First frame at each stage** (OpenCV stores colour as BGR, "
                "so the channels are swapped for display)")
    i1, i2, i3 = st.columns(3)
    i1.image(result["frame_plain"][:, :, ::-1], caption="Original", use_container_width=True)
    i2.image(result["frame_encrypted"][:, :, ::-1], caption=f"Encrypted ({result['mode']})",
             use_container_width=True)
    i3.image(result["frame_decrypted"][:, :, ::-1], caption="Decrypted", use_container_width=True)

    st.markdown("**Play them.** The encrypted clip should be static on screen "
                "and static through the speakers.")
    v1, v2, v3 = st.columns(3)
    with v1:
        st.caption("Original")
        st.video(result["paths"]["original"])
    with v2:
        st.caption(f"Encrypted with {result['mode']}")
        st.video(result["paths"]["encrypted"])
    with v3:
        st.caption("Decrypted")
        st.video(result["paths"]["decrypted"])

    if result["mode"] == "ECB":
        st.warning("Look closely at the encrypted frame. ECB encrypts every 8 byte block "
                   "on its own, so repeated blocks stay repeated and the shapes of the "
                   "original can survive. This is why ECB must not be used for media.")
    elif result["mode"] == "CTR":
        st.info("CTR encrypts a counter to make a keystream and XORs it with the data, "
                "so encryption and decryption are the same operation. It also allows any "
                "frame to be decrypted directly, which matters for seeking in a video.")
    else:
        st.info("CFB feeds each ciphertext block back into the next, so it cannot be "
                "parallelised and a single damaged byte destroys everything after it.")

    with st.expander("Where the files were written"):
        st.code("\n".join(f"{k:10} {v}" for k, v in result["paths"].items()) +
                f"\n{'ciphertext':10} {OUTDIR}/cipher_video.bin, cipher_audio.bin")

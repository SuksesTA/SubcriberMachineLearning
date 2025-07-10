#!/usr/bin/env python3
import base64, os, time
from collections import defaultdict

import numpy as np
import paho.mqtt.client as mqtt
from joblib import load
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ── Konstanta ─────────────────────────────────────────────
NONCE_LEN = 12
AD        = b""

# ── Mapping topik ke key ─────────────────────────────────
TOPIC_KEYS = {
    "AMtjeB": bytes([0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
                     0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81]),
    "BNtjEO": bytes([0x1e, 0xf2, 0xa6, 0x87, 0x2a, 0x1d, 0xa1, 0xf3,
                     0x09, 0xc6, 0xe9, 0x85, 0x9e, 0xb8, 0x7c, 0x64]),
    "YzMtje": bytes([0x19, 0x17, 0x9b, 0x0f, 0x67, 0xee, 0x01, 0x08,
                     0xa6, 0xca, 0x73, 0x42, 0xe2, 0xd3, 0xba, 0xd7]),
    "zMtjEO": bytes([0xfc, 0x19, 0x68, 0xfe, 0x2a, 0x42, 0xd8, 0x45,
                     0x39, 0xa8, 0xf7, 0x55, 0x75, 0x0c, 0xcd, 0xa0]),
    "FPuJRV": bytes([0xa3, 0xf2, 0x78, 0x5b, 0x6f, 0x00, 0x4b, 0xad,
                     0x80, 0xf3, 0xb6, 0x76, 0x1a, 0x26, 0x38, 0x9e])
}

# ── Model ML ──────────────────────────────────────────────
model  = load("SVM_model.pkl")
scaler = load("scaler.pkl")
label_map = {0: "Jalan", 1: "Lari", 2: "Mobil"}

# ── Rate-limit cache ─────────────────────────────────────
RATE_LIMIT = 1.0
LAST_SEEN  = defaultdict(lambda: {"payload": None, "ts": 0.0})

# ── Fungsi dekripsi ──────────────────────────────────────
def try_decrypt(enc_b64: bytes, key: bytes) -> str | None:
    try:
        enc = base64.b64decode(enc_b64, validate=True)
    except Exception:
        print(" Base64 decode gagal")
        return None
    if len(enc) <= NONCE_LEN + 16:
        print(" Payload terlalu pendek")
        return None

    nonce, ct_tag = enc[:NONCE_LEN], enc[NONCE_LEN:]
    aesgcm = AESGCM(key)
    try:
        pt = aesgcm.decrypt(nonce, ct_tag, AD)
        if b"," in pt:
            return pt.decode().strip()
    except Exception as e:
        print(f" Decrypt gagal: {e}")
    return None

# ── Callback MQTT ────────────────────────────────────────
def on_connect(c, u, f, rc):
    print(" Terhubung ke broker MQTT, kode:", rc)
    c.subscribe("#")

def on_message(c, u, msg):
    if msg.topic.startswith("hasil/"):
        return

    token = msg.topic.split("/")[-1]
    now = time.monotonic()

    key = TOPIC_KEYS.get(token)
    if not key:
        print(f" Tidak ada key untuk token: {token}")
        return

    plain = try_decrypt(msg.payload.strip(), key)
    if plain is None:
        print(f"[!] Tidak dapat didekripsi (topic: {msg.topic})")
        return

    if plain == LAST_SEEN[token]["payload"]:
        return
    if now - LAST_SEEN[token]["ts"] < RATE_LIMIT:
        return
    LAST_SEEN[token].update(payload=plain, ts=now)

    parts = plain.split(",")
    if len(parts) < 10:
        print(" Format data tidak valid:", plain)
        return

    device_time  = parts[0]
    batt_pct     = float(parts[1])
    lat, lon     = map(float, parts[2:4])
    temp, hum    = map(float, parts[4:6])
    x, y, z      = map(float, parts[6:9])
    speed        = float(parts[9])

    data_scaled  = scaler.transform([[x, y, z]])
    aktivitas    = label_map.get(model.predict(data_scaled)[0], "Tidak diketahui")

    csv_out = (
        f"{device_time},{batt_pct:.0f},"
        f"{lat:.5f},{lon:.5f},"
        f"{temp:.2f},{hum:.2f},"
        f"{x:.2f},{y:.2f},{z:.2f},{speed:.2f},"
        f"{aktivitas}"
    )

    print(" Plaintext:", csv_out)

    nonce_out   = os.urandom(NONCE_LEN)
    aesgcm_out  = AESGCM(key)
    ct_tag_out  = aesgcm_out.encrypt(nonce_out, csv_out.encode(), AD)
    enc_payload = base64.b64encode(nonce_out + ct_tag_out).decode()

    print(f" → hasil/{token} (len = {len(enc_payload)} B)")
    print("--------------------------------------------------")

    c.publish(f"hasil/{token}", enc_payload, qos=0, retain=True)

# ── Mulai MQTT client ────────────────────────────────────
client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message
client.connect("35.238.54.189", 1883, 60)
client.loop_forever()

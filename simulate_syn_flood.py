"""
simulate_syn_flood.py
─────────────────────
Simulates a SYN Flood DoS attack.
Sends a high volume of TCP SYN packets with spoofed source IPs
to overwhelm the target — a classic denial-of-service pattern.

NSL-KDD signature:
  - protocol: tcp
  - flag: S0 (SYN sent, no response)
  - high src_bytes, low dst_bytes
  - high count / serror_rate
"""

import random
import time
import requests

SERVER_URL = "http://127.0.0.1:4000/api/ingest"

SPOOFED_IPS = [
    f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"
    for _ in range(20)
]


def make_syn_flood_features(packet_rate: int) -> list:
    features = [0.0] * 41
    features[0]  = 0.0          # duration: 0 — connection never completes
    features[1]  = "tcp"        # protocol_type
    features[2]  = "http"       # service: targeting port 80
    features[3]  = "S0"         # flag: SYN sent, no reply — hallmark of SYN flood
    features[4]  = 48.0         # src_bytes: just the SYN packet header
    features[5]  = 0.0          # dst_bytes: no response ever arrives
    features[6]  = 0            # land
    features[7]  = 0.0          # wrong_fragment
    features[8]  = 0            # urgent
    features[22] = float(packet_rate)      # count: connections to same host
    features[23] = float(packet_rate)      # srv_count: same service
    features[24] = 1.0                     # serror_rate: 100% SYN errors
    features[25] = 1.0                     # srv_serror_rate
    features[26] = 0.0                     # rerror_rate
    features[30] = 1.0                     # same_srv_rate: all hitting same port
    return features


def run(duration_seconds: int = 30, rate_per_second: int = 50):
    print(f"💥 SYN FLOOD — sending ~{rate_per_second} packets/s for {duration_seconds}s")
    print(f"   Target service: HTTP (port 80)")
    print(f"   Spoofed source IPs: {len(SPOOFED_IPS)} unique\n")

    start  = time.time()
    sent   = 0
    errors = 0

    while time.time() - start < duration_seconds:
        src_ip      = random.choice(SPOOFED_IPS)
        packet_rate = random.randint(80, 150)   # high rate to trigger anomaly
        features    = make_syn_flood_features(packet_rate)

        try:
            res = requests.post(
                SERVER_URL,
                json={"features": features, "source_ip": src_ip},
                timeout=2.0,
            )
            if res.status_code == 200:
                pred = res.json().get("prediction", "?")
                sent += 1
                print(f"  [SYN] {src_ip:<18} rate={packet_rate:>3}  → {pred.upper()}")
        except Exception as e:
            errors += 1
            print(f"  [ERR] {e}")

        time.sleep(1 / rate_per_second)

    print(f"\n✅ Done. Sent: {sent}  Errors: {errors}")


if __name__ == "__main__":
    run(duration_seconds=30, rate_per_second=20)
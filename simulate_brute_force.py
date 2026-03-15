"""
simulate_brute_force.py
───────────────────────
Simulates a brute-force login attack over SSH.
An attacker repeatedly tries username/password combinations —
each failed attempt is one "connection" with an auth failure pattern.

NSL-KDD signature:
  - service: ssh
  - protocol: tcp
  - flag: SF (connection completes but login fails)
  - num_failed_logins: high
  - high count to same host/service
  - low src_bytes (just auth handshake, no data transferred)
"""

import random
import time
import requests

SERVER_URL = "http://127.0.0.1:4000/api/ingest"

ATTACKER_IP = "172.16.0.45"

# Simulate escalating failed login count over the attack
def make_brute_force_features(attempt: int, total_attempts: int) -> list:
    failed_ratio = min(attempt / max(total_attempts, 1), 1.0)

    features = [0.0] * 41
    features[0]  = random.uniform(0.5, 3.0)   # duration: short auth session
    features[1]  = "tcp"                        # protocol_type
    features[2]  = "ssh"                        # service: SSH brute force
    features[3]  = "SF"                         # flag: connection completes (login fails inside)
    features[4]  = random.uniform(200, 400)     # src_bytes: auth payload
    features[5]  = random.uniform(100, 300)     # dst_bytes: server challenge/rejection
    features[6]  = 0                            # land
    features[7]  = 0.0                          # wrong_fragment
    features[8]  = 0                            # urgent
    features[9]  = 0                            # hot
    features[10] = min(attempt, 5)              # num_failed_logins: grows with attempts
    features[11] = 0                            # logged_in: never succeeds
    features[12] = 0                            # num_compromised
    features[15] = 0                            # su_attempted
    features[22] = float(min(attempt * 2, 100)) # count: growing connection count
    features[23] = float(min(attempt * 2, 100)) # srv_count: all hitting SSH
    features[24] = 0.0                          # serror_rate
    features[26] = 0.0                          # rerror_rate
    features[30] = 1.0                          # same_srv_rate: always SSH
    features[31] = 0.0                          # diff_srv_rate
    features[32] = failed_ratio                 # srv_diff_host_rate
    features[35] = float(min(attempt, 255))     # dst_host_count
    features[36] = float(min(attempt, 255))     # dst_host_srv_count
    features[37] = 1.0                          # dst_host_same_srv_rate: 100% SSH
    features[38] = 0.0                          # dst_host_diff_srv_rate
    return features


def run(total_attempts: int = 40, pause_between: float = 0.5):
    print(f"🔑 BRUTE FORCE SSH — {total_attempts} login attempts")
    print(f"   Attacker IP: {ATTACKER_IP}")
    print(f"   Target service: SSH\n")

    sent   = 0
    errors = 0

    for attempt in range(1, total_attempts + 1):
        features = make_brute_force_features(attempt, total_attempts)

        try:
            res = requests.post(
                SERVER_URL,
                json={"features": features, "source_ip": ATTACKER_IP},
                timeout=2.0,
            )
            if res.status_code == 200:
                pred = res.json().get("prediction", "?")
                sent += 1
                failed = int(features[10])
                print(f"  [BRUTE] attempt {attempt:>3}/{total_attempts}"
                      f"  failed_logins={failed}  → {pred.upper()}")
        except Exception as e:
            errors += 1
            print(f"  [ERR] {e}")

        time.sleep(pause_between)

    print(f"\n✅ Done. Sent: {sent}  Errors: {errors}")


if __name__ == "__main__":
    run(total_attempts=40, pause_between=0.5)
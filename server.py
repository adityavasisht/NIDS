import csv
import os
from datetime import datetime

import joblib
import numpy as np
import pandas as pd
import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel

# ── Load ensemble model ───────────────────────────────────────────────────────
print("[BOOT] Loading ensemble model...")
try:
    ensemble_data  = joblib.load('optimized_ensemble.joblib')
    preprocessor   = ensemble_data['preprocessor']
    top_20_indices = ensemble_data['top_20_indices']
    rf_model       = ensemble_data['rf_model']
    hdc_model      = ensemble_data['hdc_model']
    classes        = ensemble_data['classes']
    FEATURE_NAMES  = list(preprocessor.feature_names_in_)
    print(f"[BOOT] Model loaded. Classes: {classes}")
    print(f"[BOOT] Expected {len(FEATURE_NAMES)} features:")
    for i, name in enumerate(FEATURE_NAMES):
        print(f"         [{i:>2}] {name}")
except Exception as e:
    print(f"[BOOT ERROR] Could not load model: {e}")
    raise SystemExit(1)

app = FastAPI(title="NIPS Prevention Server")

LOG_FILE = "live_traffic.csv"


def init_log():
    with open(LOG_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Time", "Source_IP", "Protocol", "Status", "Confidence", "Method"])


init_log()
print(f"[BOOT] Log file initialised: {LOG_FILE}\n")


class PacketData(BaseModel):
    features: list
    source_ip: str


def heuristic_check(features: list):
    """
    Rule-based fallback for clear-cut attack signatures.
    Returns 'anomaly', 'normal', or None (defer to ML).
    """
    try:
        flag        = features[3]
        serror_rate = float(features[24])
        rerror_rate = float(features[26])
        count       = float(features[22])
        src_bytes   = float(features[4])
        dst_bytes   = float(features[5])
        failed      = float(features[10])
        logged_in   = float(features[11])
        hot         = float(features[9])
        proto       = features[1]

        # SYN Flood: S0 flag + high serror_rate + high count
        if flag == "S0" and serror_rate >= 0.9 and count > 50:
            return "anomaly"

        # Port scan: REJ/RSTO flag + near-zero bytes + high rerror_rate
        if flag in ("REJ", "RSTO", "RSTOS0") and rerror_rate >= 0.8 and src_bytes < 100:
            return "anomaly"

        # Brute force: many failed logins, not authenticated
        if failed >= 3 and logged_in == 0 and count > 20:
            return "anomaly"

        # R2L: hot indicators + not logged in + exploit-sized payload
        if hot >= 3 and logged_in == 0 and 200 < src_bytes < 10000 and dst_bytes < 500:
            return "anomaly"

        # UDP flood: massive src_bytes over UDP with high count
        if proto == "udp" and src_bytes > 5000 and count > 80:
            return "anomaly"

    except (IndexError, TypeError, ValueError):
        pass

    return None  # defer to ML


@app.post("/api/ingest")
async def ingest_packet(data: PacketData):
    try:
        features = data.features

        if len(features) != len(FEATURE_NAMES):
            raise ValueError(
                f"Feature length mismatch: got {len(features)}, "
                f"expected {len(FEATURE_NAMES)}"
            )

        # ── Heuristic check first ─────────────────────────────────────────
        heuristic_result = heuristic_check(features)

        if heuristic_result is not None:
            prediction = heuristic_result
            confidence = 1.0
            method     = "heuristic"
            print(f"[HEURISTIC] {data.source_ip} flag={features[3]} "
                  f"serr={features[24]} rerr={features[26]} count={features[22]} "
                  f"→ {prediction.upper()}")

        else:
            # ── ML inference ──────────────────────────────────────────────
            df             = pd.DataFrame([features], columns=FEATURE_NAMES)
            processed      = preprocessor.transform(df)
            features_top20 = processed[:, top_20_indices]

            rf_proba  = rf_model.predict_proba(features_top20)
            hdc_proba = hdc_model.predict_proba(features_top20)
            avg_proba = (rf_proba + hdc_proba) / 2

            pred_idx   = int(np.argmax(avg_proba))
            prediction = classes[pred_idx]
            confidence = float(np.max(avg_proba))
            method     = "ml"

            print(f"[ML] {data.source_ip:<18} → {prediction.upper():<8} "
                  f"conf={confidence:.2f}  "
                  f"rf={np.round(rf_proba[0], 2)}  hdc={np.round(hdc_proba[0], 2)}")

        # ── Append to log ─────────────────────────────────────────────────
        time_now = datetime.now().strftime("%H:%M:%S")
        proto    = features[1] if isinstance(features[1], str) else "unknown"

        with open(LOG_FILE, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([time_now, data.source_ip, proto,
                             prediction, f"{confidence:.2f}", method])

        return {"prediction": prediction, "confidence": confidence, "method": method}

    except ValueError as ve:
        print(f"[ERROR] Value error: {ve}")
        return {"prediction": "error", "details": str(ve)}
    except Exception as e:
        print(f"[ERROR] Unhandled: {e}")
        import traceback; traceback.print_exc()
        return {"prediction": "error", "details": str(e)}


@app.post("/api/block")
async def block_ip(ip: str):
    print(f"[FIREWALL] Blocking {ip}")
    os.system(f'echo "block drop out quick on en0 from any to {ip}" | sudo pfctl -f -')
    os.system(f"say 'Threat from {ip} blocked'")
    return {"status": "blocked", "ip": ip}


if __name__ == "__main__":
    print("[BOOT] Starting NIPS server on http://127.0.0.1:4000")
    print("[BOOT] Docs at http://127.0.0.1:4000/docs\n")
    uvicorn.run(app, host="127.0.0.1", port=4000, log_level="warning")
import time
import requests
from scapy.all import sniff, IP, TCP, UDP, ICMP

SERVER_URL = "http://127.0.0.1:4000/api/ingest"

PORT_MAP = {
    80: 'http',
    443: 'http',
    22: 'ssh',
    53: 'domain',
}

flow_tracker = {}


def process_packet(packet):
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    now = time.time()

    # Stateful flow tracking: count packets from this IP in last 2 seconds
    if src_ip not in flow_tracker:
        flow_tracker[src_ip] = []
    flow_tracker[src_ip] = [t for t in flow_tracker[src_ip] if now - t < 2]
    flow_tracker[src_ip].append(now)
    packet_rate = len(flow_tracker[src_ip])

    # Detect protocol
    if packet.haslayer(TCP):
        proto = "tcp"
    elif packet.haslayer(UDP):
        proto = "udp"
    elif packet.haslayer(ICMP):
        proto = "icmp"
    else:
        proto = "other"

    # Resolve service from port
    sport = packet.sport if hasattr(packet, 'sport') else 0
    dport = packet.dport if hasattr(packet, 'dport') else 0
    service = PORT_MAP.get(dport, PORT_MAP.get(sport, 'private'))

    # Build NSL-KDD feature vector (41 features)
    features = [0.0] * 41
    features[0] = 0.0                  # duration
    features[1] = proto                # protocol_type  (string)
    features[2] = service              # service        (string)
    features[3] = 'SF'                 # flag           (string)
    features[4] = float(len(packet))   # src_bytes
    features[5] = 0.0                  # dst_bytes

    # Real-time stats injected into ML vector
    features[22] = float(packet_rate)  # count: connections to same host last 2s
    features[23] = 0.0
    if packet_rate > 200:              # only flag as sync error on extreme floods
        features[24] = 1.0

    # Send to inference server
    payload = {"features": features, "source_ip": src_ip}
    try:
        res = requests.post(SERVER_URL, json=payload, timeout=2.0)
        if res.status_code == 200:
            pred = res.json().get("prediction", "unknown")
            tag = "🚨 ANOMALY" if pred == "anomaly" else "✅ normal "
            print(f"[{proto.upper():>4}] {src_ip:<16} rate={packet_rate:>3}pkt/2s  {tag}")
        else:
            print(f"[WARN] Server returned {res.status_code}")
    except requests.exceptions.ConnectionError:
        print("[ERROR] Cannot reach server — is server.py running?")
    except requests.exceptions.Timeout:
        print("[ERROR] Server timed out (inference taking >2s)")
    except Exception as e:
        print(f"[ERROR] Unexpected: {e}")


if __name__ == "__main__":
    print("🚀 NIPS Sniffer active on loopback (lo0)")
    print(f"   Sending to: {SERVER_URL}")
    print("   Press Ctrl+C to stop.\n")
    sniff(prn=process_packet, store=0, iface="lo0")
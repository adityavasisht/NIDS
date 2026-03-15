import socket
import time

def flood():
    print("🚀 Launching TCP Flood Simulation to 127.0.0.1:4000...")
    # Send 200 rapid connection attempts
    for i in range(200):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.01)
            s.connect(("127.0.0.1", 4000))
            s.close()
        except:
            pass
    print("✅ Flood complete.")

if __name__ == "__main__":
    flood()
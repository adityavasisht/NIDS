import time
import requests
import csv

SERVER_URL = "http://127.0.0.1:4000/api/ingest"
TEST_FILE = "KDDTest+.txt"
DELAY = 1.0 / 20.0  # Target ~20 packets per second

def run_simulation():
    print(f"Starting Live Traffic Simulation -> {SERVER_URL}")
    print("-" * 50)
    
    with open(TEST_FILE, 'r') as file:
        reader = csv.reader(file)
        
        for count, row in enumerate(reader, 1):
            # Extract exactly the 41 features (ignore label and difficulty)
            features = row[:41]
            
            # Convert numeric strings to floats, leave categoricals as strings
            parsed_features = []
            for i, val in enumerate(features):
                if i in [1, 2, 3]: # protocol_type, service, flag
                    parsed_features.append(val)
                else:
                    parsed_features.append(float(val))
            
            payload = {"features": parsed_features}
            
            try:
                start_time = time.time()
                response = requests.post(SERVER_URL, json=payload)
                
                if response.status_code == 200:
                    result = response.json()
                    prediction = result["prediction"]
                    
                    protocol = parsed_features[1].upper()
                    
                    # Formatting terminal log output
                    if prediction == 'anomaly':
                        print(f"[!] ALERT | Protocol: {protocol:<4} | Result: ANOMALY 🚨")
                    else:
                        print(f"[*] PASS  | Protocol: {protocol:<4} | Result: NORMAL  ✅")
                else:
                    print(f"[Error] Server returned {response.status_code}")
                    
            except requests.exceptions.RequestException as e:
                print(f"[Error] Connection failed: {e}")
                break
            
            # Rate limiting logic to maintain 20 req/sec
            elapsed = time.time() - start_time
            sleep_time = max(0, DELAY - elapsed)
            time.sleep(sleep_time)

if __name__ == "__main__":
    run_simulation()
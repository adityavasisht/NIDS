AI-Powered Hybrid NIPS (Network Intrusion Prevention System)
An intelligent, real-time Network Intrusion Prevention System (NIPS) that leverages a Hybrid AI Ensemble—combining classical Random Forest with neuro-inspired Hyperdimensional Computing (HDC)—to detect and actively block cyber threats at the kernel level.

🚀 Key Features
Hybrid AI Engine: Dual-model classification using Random Forest and HDC for 99%+ accuracy.

Real-Time Sniffing: Live Deep Packet Inspection (DPI) powered by the Scapy library.

Active Prevention: Automated IP blacklisting via OS kernel-level firewall orchestration (pfctl).

Interactive Dashboard: A centralized command center built with Streamlit for live threat visualization.

Attack Simulation: Built-in scripts to safely simulate DoS (SYN Flood) and R2L (Brute Force) attacks.

📂 Project Structure
Plaintext
nids_project/
├── hdc_model.py            # Implementation of 10,000-D Hyperdimensional Computing
├── train_ensemble.py       # Training pipeline for the Hybrid AI Ensemble
├── server.py               # Backend API for real-time packet classification
├── capture.py              # Scapy-based live packet sniffer & feature extractor
├── dashboard.py            # Streamlit-based UI for real-time monitoring
├── attack.py               # Active prevention logic (firewall blocking)
├── simulators/             # Scripts to simulate SYN Floods and Brute Force
└── optimized_ensemble.joblib # Serialized pre-trained model
🛠️ Tech Stack
Language: Python 3.10+

AI/ML: Scikit-learn, NumPy, Hyperdimensional Computing (HDC)

Networking: Scapy (Packet Sniffing & DPI)

Dashboard: Streamlit

Dataset: NSL-KDD (Standard Benchmark)

⚙️ Installation & Setup
1. Clone the Repository
Bash
git clone https://github.com/your-username/nids_project.git
cd nids_project
2. Setup Environment
Bash
# Create virtual environment
python -m venv venv

# Activate (macOS/Linux)
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
3. Run the System
To start the full protection suite, you need to run the server and the dashboard:

Bash
# Terminal 1: Start the Inference Server
python server.py

# Terminal 2: Start the Monitoring Dashboard
streamlit run dashboard.py
📊 Performance
Baseline Accuracy: 99.86% (NSL-KDD)

Inference Latency: < 15ms per packet

Threats Detected: DoS, Probe, R2L, U2R

🛡️ Prevention Mechanism
When a threat is detected with high confidence by the ensemble, the system automatically executes:

Bash
sudo pfctl -t blocked_ips -T add <attacker_ip>
This drops all subsequent packets from the source at the OS kernel level before they can reach your applications.

🤝 Contributing
Contributions are welcome! If you'd like to integrate modern datasets like CIC-IDS2017 or improve the HDC vector projection logic, feel free to open a Pull Request.

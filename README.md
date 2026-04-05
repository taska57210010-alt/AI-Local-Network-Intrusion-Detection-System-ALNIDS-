# 🛡️ AI Local Network Intrusion Detection System (ALIDS)

A Python-based network intrusion detection system with clean architecture, real-time packet capture, feature extraction, and rule-based attack detection.

## Features

✅ **Real-time Packet Capture**: Uses Scapy to capture live network traffic
✅ **Feature Extraction**: Calculates key metrics every 5 seconds
✅ **Rule-based Detection**: Multiple detection rules for common attacks
✅ **Continuous Monitoring**: Runs as a daemon with time-windowed analysis
✅ **Interactive Dashboard**: Streamlit-based web dashboard for visualization
✅ **Modular Architecture**: Clean separation of concerns for easy extension
✅ **ML-Ready**: Designed to integrate machine learning models later

## Project Structure

```
SOC/
├── main.py              # Entry point - orchestrates all components
├── sniffer.py          # Packet capture module
├── features.py         # Feature extraction logic
├── detector.py         # Attack detection rules
├── dashboard.py        # Streamlit web dashboard
├── requirements.txt    # Python dependencies
└── README.md           # This file
```

## Detected Attacks

The system currently detects:

1. **DDoS Attacks**: High packet rate (>100 req/sec) + high SYN count (>50)
2. **SYN Floods**: Abnormally high ratio of SYN packets in TCP traffic
3. **Unusual Traffic**: Sustained high traffic volume without SYN flood indicators
4. **Port Scans**: Single source scanning multiple destination IPs

## Installation

### Requirements
- Python 3.7+
- Root/Administrator privileges (required for packet sniffing)
- Linux/macOS (Windows requires WinPcap/Npcap)

### Setup

```bash
# Navigate to the project directory
cd SOC/

# Install dependencies
pip install -r requirements.txt

# Or with pip3
pip3 install -r requirements.txt
```

## Usage

### 1. Start the Main IDS System (Required)

Run with **root privileges**:

```bash
sudo python3 main.py
```

This will:
- Start capturing packets in real-time
- Extract features every 5 seconds
- Detect potential attacks
- Print alerts to console

### 2. View the Dashboard (Optional)

In **another terminal** (no root needed):

```bash
streamlit run dashboard.py
```

This will open a web dashboard at `http://localhost:8501` showing:
- Real-time traffic statistics
- Requests per second
- Unique IP addresses
- SYN packet count
- Active alerts
- Configurable detection thresholds

## Code Examples

### Running the IDS Programmatically

```python
from main import NetworkIDS

# Create IDS with 5-second window
ids = NetworkIDS(window_size=5)

# Start monitoring
ids.start(timeout=3600)  # 1 hour timeout
```

### Integrating Custom Detection Rules

```python
from detector import AttackDetector, Alert

detector = AttackDetector()

# Customize thresholds
detector.set_threshold('high_requests_per_sec', 150)
detector.set_threshold('syn_flood_packets', 100)

# Run detection
features = {...}  # From feature extractor
alerts = detector.detect(features)

for alert in alerts:
    print(f"{alert.severity}: {alert.message}")
```

### Accessing Real-time Features

```python
from sniffer import PacketSniffer
from features import FeatureExtractor

sniffer = PacketSniffer()
extractor = FeatureExtractor(window_size=5)

# Start sniffing in background
# ... (in separate thread)

# Get current features
packets = sniffer.get_buffer()
features = extractor.extract_features(packets)

print(f"Requests/sec: {features['requests_per_second']:.2f}")
print(f"Unique IPs: {features['unique_source_ips']}")
```

## Architecture Overview

```
PacketSniffer (sniffer.py)
    ↓ (raw packets)
FeatureExtractor (features.py)
    ↓ (calculated metrics)
AttackDetector (detector.py)
    ↓ (alerts)
Logging & Dashboard (main.py, dashboard.py)
```

### Module Responsibilities

**sniffer.py** - Packet Capture
- Captures network packets in real-time
- Parses basic information (IP, protocol, flags)
- Maintains a bounded packet buffer
- Supports callback functions for extensibility

**features.py** - Feature Extraction
- Calculates metrics from packet buffer
- Time-windowed statistics
- Metrics: requests/sec, unique IPs, SYN count, average packet size
- Easy to add new features

**detector.py** - Attack Detection
- Rule-based detection logic
- Configurable thresholds
- Different severity levels (LOW, MEDIUM, HIGH, CRITICAL)
- Designed for ML model integration

**main.py** - Orchestration
- Coordinates all components
- Manages detection loop (every 5 seconds by default)
- Logs statistics and alerts
- Handles graceful shutdown

**dashboard.py** - Visualization
- Real-time web dashboard using Streamlit
- Interactive threshold adjustment
- Alert display with color-coding
- Protocol breakdown charts

## Configuration

### Adjust Detection Window

In `main.py`:
```python
ids = NetworkIDS(window_size=10)  # 10-second windows instead of 5
```

### Modify Thresholds

The detector uses these default thresholds (can be adjusted):

```python
{
    'high_requests_per_sec': 100,      # Packets/sec
    'syn_flood_packets': 50,           # SYN packet count
    'syn_ratio_threshold': 0.3,        # SYN ratio in TCP traffic
    'unusual_unique_ips': 50,          # Source IP count
    'port_scan_threshold': 100,        # Destination IP count
}
```

Change thresholds programmatically:
```python
detector.set_threshold('high_requests_per_sec', 150)
detector.set_threshold('syn_flood_packets', 100)
```

## Extending the System

### Adding Custom Detection Rules

In `detector.py`, add a new rule in the `detect()` method:

```python
# Your custom rule
if some_condition:
    self.alerts.append(Alert(
        alert_type="CUSTOM_ATTACK",
        severity="HIGH",
        message="Your alert message",
        triggered_features={...}
    ))
```

### Adding Machine Learning

The architecture supports ML integration:

```python
from detector import AttackDetector, Alert
import joblib

class MLDetector(AttackDetector):
    def __init__(self, model_path):
        super().__init__()
        self.model = joblib.load(model_path)
    
    def detect(self, features):
        # Use ML model to predict anomalies
        prediction = self.model.predict([features])
        if prediction[0] == 1:  # Anomaly detected
            # Create alert
        return self.alerts
```

### Adding New Features

In `features.py`, extract more from packets:

```python
def extract_features(self, packets):
    features = {...}  # Existing features
    
    # Add new features
    features['icmp_packets'] = sum(1 for p in packets if p['protocol'] == 'ICMP')
    features['max_packet_size'] = max(p['size'] for p in packets)
    
    return features
```

## Troubleshooting

### "Permission denied" when sniffing packets

**Solution**: Run with sudo
```bash
sudo python3 main.py
```

### No packets captured

**Verify:**
1. You have internet activity (ping, browse, etc.)
2. Running with root privileges
3. Network interface is not in promiscuous mode disabled
4. Firewall not blocking Scapy

### High CPU usage

**Optimize:**
1. Increase window_size to reduce detection frequency
2. Reduce packet buffer size in PacketSniffer
3. Use firewall rules to filter traffic before sniffing

## Performance Notes

- **Packet Buffer Size**: Default 1000 packets (adjustable in `PacketSniffer.__init__`)
- **Detection Window**: Default 5 seconds (adjustable in `main.py`)
- **Memory Usage**: Approximately 1-10 MB depending on traffic
- **CPU Usage**: 5-15% on typical networks (varies with packet rate)

## Future Enhancements

- [ ] Machine learning model integration
- [ ] Persistent alert logging to database
- [ ] Automated threat intelligence feeds
- [ ] Advanced statistical anomaly detection
- [ ] Protocol deep packet inspection (DPI)
- [ ] Encrypted traffic fingerprinting
- [ ] Distributed IDS across multiple sensors
- [ ] Real-time YARA rule integration

## Disclaimer

This is an educational project. For production use:
- Validate detection rules in your environment
- Implement persistent logging
- Set up alert notification systems
- Use alongside professional IDS solutions (Suricata, Snort, Zeek)
- Ensure compliance with local network monitoring laws

## License

MIT License

## Author

Cybersecurity Engineering Team

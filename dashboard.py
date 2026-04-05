"""
Streamlit Dashboard for Network IDS
Real-time visualization of network traffic and security alerts.
"""

import streamlit as st
import logging
import time
from datetime import datetime
from collections import deque
from sniffer import PacketSniffer
from features import FeatureExtractor
from detector import AttackDetector

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configure page
st.set_page_config(
    page_title="Network IDS Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state for the sniffing system
if 'sniffer' not in st.session_state:
    try:
        st.session_state.sniffer = PacketSniffer()
        st.session_state.feature_extractor = FeatureExtractor(window_size=3)
        st.session_state.detector = AttackDetector()
        st.session_state.metrics_history = deque(maxlen=50)
        st.session_state.alerts_history = deque(maxlen=100)
        st.session_state.sniffing = False
        st.session_state.last_update = time.time()
        logger.info("IDS components initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize IDS components: {e}")
        st.error(f"Failed to initialize IDS: {str(e)}")


def get_current_metrics():
    """
    Get current network metrics from the sniffer.
    
    Returns:
        Dictionary with features, alerts, and timestamp, or None if no data
    """
    try:
        packets = st.session_state.sniffer.get_buffer()
        if len(packets) == 0:
            return None

        features = st.session_state.feature_extractor.extract_features(packets)
        alerts = st.session_state.detector.detect(features)

        return {
            'features': features,
            'alerts': alerts,
            'timestamp': time.time()
        }
    except Exception as e:
        logger.error(f"Error getting metrics: {e}")
        return None


# Title and header
st.markdown("""
    <style>
    .main-header {
        font-size: 40px;
        font-weight: bold;
        color: #ff6b6b;
        text-align: center;
        margin-bottom: 20px;
    }
    .status-safe {
        color: #51cf66;
        font-weight: bold;
    }
    .status-warning {
        color: #ffd93d;
        font-weight: bold;
    }
    .status-danger {
        color: #ff6b6b;
        font-weight: bold;
    }
    </style>
    <div class="main-header">
    🛡️ Network Intrusion Detection System (IDS)
    </div>
""", unsafe_allow_html=True)

st.markdown("---")

# Sidebar controls
with st.sidebar:
    st.header("⚙️ Settings")
    
    window_size = st.slider(
        "Detection Window (seconds)",
        min_value=1,
        max_value=10,
        value=5,
        help="Time window for feature calculation"
    )
    st.session_state.feature_extractor.set_window_size(window_size)

    st.markdown("---")
    st.subheader("Detection Thresholds")
    
    thresholds = st.session_state.detector.get_thresholds()
    
    new_high_rps = st.number_input(
        "High Requests/sec",
        value=int(thresholds['high_requests_per_sec']),
        help="Threshold for detecting high traffic"
    )
    st.session_state.detector.set_threshold('high_requests_per_sec', float(new_high_rps))

    new_syn_flood = st.number_input(
        "SYN Flood Threshold",
        value=int(thresholds['syn_flood_packets']),
        help="Number of SYN packets to trigger alert"
    )
    st.session_state.detector.set_threshold('syn_flood_packets', float(new_syn_flood))

    new_port_scan = st.number_input(
        "Port Scan Threshold",
        value=int(thresholds['port_scan_threshold']),
        help="Number of destination IPs to detect port scan"
    )
    st.session_state.detector.set_threshold('port_scan_threshold', float(new_port_scan))

    st.markdown("---")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("🔄 Refresh Now", use_container_width=True):
            st.rerun()
    with col2:
        auto_refresh = st.checkbox("Auto-refresh (5s)", value=False)
        st.session_state.auto_refresh = auto_refresh


# Main content area
col1, col2, col3, col4 = st.columns(4)

# Get current metrics
metrics = get_current_metrics()

if metrics is None:
    st.info("⏳ Waiting for packets... Make sure the IDS main.py is running with root privileges.")
    st.info("Run: `sudo python main.py` in another terminal")
else:
    features = metrics['features']
    alerts = metrics['alerts']

    # Metric Cards
    with col1:
        st.metric(
            "📊 Requests/sec",
            f"{features['requests_per_second']:.2f}",
            help="Packets per second"
        )

    with col2:
        st.metric(
            "🌐 Unique Source IPs",
            features['unique_source_ips'],
            help="Number of unique source IP addresses"
        )

    with col3:
        st.metric(
            "📍 Unique Dest IPs",
            features['unique_destination_ips'],
            help="Number of unique destination IP addresses"
        )

    with col4:
        st.metric(
            "🚩 SYN Packets",
            features['tcp_syn_count'],
            help="Number of TCP SYN packets"
        )

# Alert Section
st.markdown("---")
st.header("🚨 Security Alerts")

if metrics and metrics['alerts']:
    for alert in metrics['alerts']:
        severity_color = {
            'LOW': '#FFA500',
            'MEDIUM': '#FF8C00',
            'HIGH': '#FF4500',
            'CRITICAL': '#DC143C'
        }
        color = severity_color.get(alert.severity, '#FF6B6B')
        
        st.markdown(f"""
        <div style="border-left: 4px solid {color}; padding: 10px; margin: 10px 0; background-color: #f8f9fa; border-radius: 4px;">
            <b>{alert.alert_type}</b> <span style="color: {color};">●</span><br/>
            <small>Severity: <b>{alert.severity}</b></small><br/>
            <small>{alert.message}</small>
        </div>
        """, unsafe_allow_html=True)
else:
    st.success("✅ No active alerts - Traffic appears normal!")

# Detailed Metrics
st.markdown("---")
st.header("📈 Detailed Network Statistics")

if metrics:
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Protocol Breakdown")
        protocol_data = {
            'TCP': features['tcp_packets'],
            'UDP': features['udp_packets'],
            'Other': features['packet_count'] - features['tcp_packets'] - features['udp_packets']
        }
        st.bar_chart(protocol_data)

    with col2:
        st.subheader("Key Metrics")
        metrics_table = {
            'Metric': [
                'Total Packets',
                'TCP Packets',
                'UDP Packets',
                'TCP SYN Packets',
                'Avg Packet Size'
            ],
            'Value': [
                features['packet_count'],
                features['tcp_packets'],
                features['udp_packets'],
                features['tcp_syn_count'],
                f"{features['average_packet_size']:.2f} bytes"
            ]
        }
        st.table(metrics_table)

# Footer
st.markdown("---")

col1, col2, col3 = st.columns(3)
with col1:
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.markdown(f"**Last updated:** {current_time}")

with col2:
    if st.button("🔄 Refresh Now", use_container_width=True):
        st.rerun()

with col3:
    auto_refresh = st.checkbox("Auto-refresh (5s)", value=True)
    if auto_refresh:
        time.sleep(5)
        st.rerun()

st.markdown("""
<div style="text-align: center; color: #666; font-size: 11px; margin-top: 20px;">
    <p>🛡️ Network IDS Dashboard | Production Ready</p>
    <p>For best results, run this dashboard while main.py is executing with root privileges</p>
</div>
""", unsafe_allow_html=True)

"""
Network Intrusion Detection System (IDS) - Main Entry Point
Orchestrates packet sniffing, feature extraction, and attack detection.

This system runs continuously in a configurable detection window,
capturing packets and analyzing them for signs of network attacks.
"""

import logging
import time
import threading
import sys
from typing import Optional
from sniffer import PacketSniffer
from features import FeatureExtractor
from detector import AttackDetector

# Configure logging with more detail
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('ids.log')
    ]
)
logger = logging.getLogger(__name__)


class NetworkIDS:
    """
    Main IDS system that coordinates all components.
    """

    def __init__(self, window_size: int = 5):
        """
        Initialize the IDS.
        
        Args:
            window_size: Time window in seconds for feature calculation
        """
        self.sniffer = PacketSniffer()
        self.feature_extractor = FeatureExtractor(window_size=window_size)
        self.detector = AttackDetector()
        
        self.running = False
        self.window_size = window_size
        self.last_features = None
        self.statistics = {
            'total_packets_processed': 0,
            'total_alerts': 0,
            'alerts_by_type': {}
        }

    def start(self, timeout: Optional[int] = None):
        """
        Start the IDS system.
        
        Args:
            timeout: Optional timeout in seconds
        """
        logger.info("=" * 70)
        logger.info("🛡️  Network IDS Started")
        logger.info(f"Window size: {self.window_size} seconds")
        logger.info(f"Detection thresholds: {self.detector.get_thresholds()}")
        logger.info("=" * 70)

        self.running = True

        # Start sniffing in a background thread
        sniffer_thread = threading.Thread(
            target=self.sniffer.start_sniffing,
            kwargs={'timeout': timeout},
            daemon=True,
            name="PacketSniffer"
        )
        sniffer_thread.start()
        logger.info("Packet sniffer thread started")

        # Main detection loop
        try:
            while self.running:
                time.sleep(self.window_size)
                self._detection_cycle()
        except KeyboardInterrupt:
            logger.info("\n" + "=" * 70)
            logger.info("🛑 IDS Stopped by User (Ctrl+C)")
            logger.info("=" * 70)
            self.stop()
        except Exception as e:
            logger.error(f"Error in main loop: {e}", exc_info=True)
            self.stop()

    def _detection_cycle(self):
        """
        Main detection cycle - runs every window_size seconds.
        1. Get packets from buffer
        2. Extract features
        3. Detect attacks
        4. Log alerts
        """
        try:
            # Get current packets from buffer
            packets = self.sniffer.get_buffer()

            if len(packets) == 0:
                logger.debug("No packets captured in this window")
                return

            # Extract features
            features = self.feature_extractor.extract_features(packets)
            self.last_features = features
            self.statistics['total_packets_processed'] += len(packets)

            # Detect attacks
            alerts = self.detector.detect(features)

            # Log results
            self._log_detection_cycle(features, alerts)

            # Clear buffer for next cycle
            self.sniffer.clear_buffer()
            
        except Exception as e:
            logger.error(f"Error in detection cycle: {e}", exc_info=True)

    def _log_detection_cycle(self, features: dict, alerts: list):
        """
        Log the results of a detection cycle.
        
        Args:
            features: Extracted network features
            alerts: List of detected alerts
        """
        # Log normal statistics
        logger.info("-" * 60)
        logger.info("📊 Network Statistics:")
        logger.info(f"  Packets: {features['packet_count']}")
        logger.info(f"  Requests/sec: {features['requests_per_second']:.2f}")
        logger.info(f"  Unique Source IPs: {features['unique_source_ips']}")
        logger.info(f"  Unique Dest IPs: {features['unique_destination_ips']}")
        logger.info(f"  TCP SYN Packets: {features['tcp_syn_count']}")
        logger.info(f"  TCP Packets: {features['tcp_packets']}")
        logger.info(f"  UDP Packets: {features['udp_packets']}")
        logger.info(f"  Avg Packet Size: {features['average_packet_size']:.2f} bytes")

        # Log alerts if any
        if alerts:
            logger.warning(f"\n⚠️  {len(alerts)} ALERT(S) DETECTED!")
            for alert in alerts:
                self._log_alert(alert)
                # Update statistics
                self.statistics['total_alerts'] += 1
                alert_type = alert.alert_type
                self.statistics['alerts_by_type'][alert_type] = \
                    self.statistics['alerts_by_type'].get(alert_type, 0) + 1
        else:
            logger.info("✅ No alerts - Traffic appears normal")

    def _log_alert(self, alert):
        """
        Log a single alert with formatting.
        
        Args:
            alert: Alert object to log
        """
        severity_emoji = {
            'LOW': '🟡',
            'MEDIUM': '🟠',
            'HIGH': '🔴',
            'CRITICAL': '🔴🔴'
        }
        emoji = severity_emoji.get(alert.severity, '⚠️')

        logger.warning(f"{emoji} [{alert.severity}] {alert.alert_type}")
        logger.warning(f"   Message: {alert.message}")
        logger.warning(f"   Triggered by: {alert.triggered_features}")

    def stop(self):
        """Stop the IDS system."""
        self.running = False
        logger.info("\nFinal Statistics:")
        logger.info(f"  Total packets processed: {self.statistics['total_packets_processed']}")
        logger.info(f"  Total alerts triggered: {self.statistics['total_alerts']}")
        logger.info(f"  Alerts by type: {self.statistics['alerts_by_type']}")

    def get_statistics(self) -> dict:
        """Get current IDS statistics."""
        return self.statistics.copy()

    def get_last_features(self) -> Optional[dict]:
        """Get features from the last detection cycle."""
        return self.last_features


def main():
    """Main entry point for the IDS."""
    # Create IDS with 5-second detection window
    ids = NetworkIDS(window_size=5)

    # Start the system (runs until Ctrl+C)
    ids.start(timeout=None)


if __name__ == "__main__":
    main()

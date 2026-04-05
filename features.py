"""
Feature Extraction Module
Calculates network traffic features from captured packets.

This module extracts meaningful features from raw packets for analysis:
- Traffic volume metrics (requests per second, packet count)
- IP diversity metrics (unique source/destination IPs)
- Protocol-specific metrics (TCP SYN count, UDP packets)
- Traffic statistics (average packet size)
"""

from typing import Dict, List, Optional
from collections import defaultdict
import time
import logging

logger = logging.getLogger(__name__)


class FeatureExtractor:
    """
    Extracts network traffic features from packets.
    Designed to work with time windows (e.g., 5-second intervals).
    """

    def __init__(self, window_size: int = 5):
        """
        Initialize the feature extractor.
        
        Args:
            window_size: Time window in seconds for feature calculation
            
        Raises:
            ValueError: If window_size is invalid
        """
        if window_size <= 0:
            raise ValueError("window_size must be positive")
            
        self.window_size = window_size
        self.last_calculation_time = time.time()
        self.feature_history = []
        logger.info(f"FeatureExtractor initialized with window size: {window_size}s")

    def extract_features(self, packets: List[Dict]) -> Dict:
        """
        Extract features from a list of packets.
        
        Features calculated:
        - packet_count: Total packets in window
        - requests_per_second: Packet rate
        - unique_source_ips: Count of unique source IPs
        - unique_destination_ips: Count of unique destination IPs
        - tcp_syn_count: Count of TCP SYN packets
        - tcp_packets: Total TCP packets
        - udp_packets: Total UDP packets
        - average_packet_size: Mean packet size
        
        Args:
            packets: List of packet dictionaries from PacketSniffer
            
        Returns:
            Dictionary containing extracted features
            
        Raises:
            TypeError: If packets is not a list
        """
        if not isinstance(packets, list):
            raise TypeError("packets must be a list")
            
        features = {
            'packet_count': len(packets),
            'requests_per_second': 0.0,
            'unique_source_ips': 0,
            'unique_destination_ips': 0,
            'tcp_syn_count': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'average_packet_size': 0.0,
        }

        if len(packets) == 0:
            logger.debug("No packets to extract features from")
            return features

        try:
            # Count requests per second
            current_time = time.time()
            time_elapsed = current_time - self.last_calculation_time
            if time_elapsed > 0:
                features['requests_per_second'] = len(packets) / time_elapsed
            self.last_calculation_time = current_time

            # Extract IP addresses and metrics
            source_ips = set()
            dest_ips = set()
            total_size = 0

            for packet in packets:
                # Validate packet structure
                if not isinstance(packet, dict):
                    logger.debug(f"Invalid packet format: {type(packet)}")
                    continue
                    
                # Collect unique IPs
                src_ip = packet.get('src_ip')
                dst_ip = packet.get('dst_ip')
                
                if src_ip:
                    source_ips.add(src_ip)
                if dst_ip:
                    dest_ips.add(dst_ip)

                # Count SYN packets
                if packet.get('is_syn', False):
                    features['tcp_syn_count'] += 1

                # Count by protocol
                protocol = packet.get('protocol')
                if protocol == 'TCP':
                    features['tcp_packets'] += 1
                elif protocol == 'UDP':
                    features['udp_packets'] += 1

                # Accumulate packet sizes
                size = packet.get('size', 0)
                if isinstance(size, (int, float)) and size > 0:
                    total_size += size

            # Calculate final features
            features['unique_source_ips'] = len(source_ips)
            features['unique_destination_ips'] = len(dest_ips)
            
            if len(packets) > 0:
                features['average_packet_size'] = total_size / len(packets)

            # Store in history for trend analysis
            self.feature_history.append(features.copy())
            if len(self.feature_history) > 100:  # Keep last 100 samples
                self.feature_history.pop(0)
                
            logger.debug(f"Extracted features from {len(packets)} packets")
            
        except Exception as e:
            logger.error(f"Error extracting features: {e}")

        return features

    def get_window_size(self) -> int:
        """
        Get the current window size in seconds.
        
        Returns:
            Window size in seconds
        """
        return self.window_size

    def set_window_size(self, window_size: int) -> None:
        """
        Set a new window size.
        
        Args:
            window_size: New window size in seconds
            
        Raises:
            ValueError: If window_size is invalid
        """
        if window_size <= 0:
            raise ValueError("window_size must be positive")
        self.window_size = window_size
        logger.info(f"Window size updated to {window_size}s")

    def get_average_features(self, last_n: int = 10) -> Optional[Dict]:
        """
        Get average features over last N samples.
        
        Useful for trend analysis and anomaly detection.
        
        Args:
            last_n: Number of recent samples to average
            
        Returns:
            Dictionary with averaged features, or None if not enough data
        """
        if len(self.feature_history) < last_n:
            return None
            
        try:
            recent = self.feature_history[-last_n:]
            avg_features = {}
            
            for key in recent[0].keys():
                values = [f[key] for f in recent if isinstance(f[key], (int, float))]
                if values:
                    avg_features[key] = sum(values) / len(values)
            
            return avg_features
        except Exception as e:
            logger.error(f"Error calculating average features: {e}")
            return None

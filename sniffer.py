"""
Packet Sniffer Module
Captures network packets and parses basic information.
"""

from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
from typing import Dict, List, Callable, Optional
import logging
import os

logger = logging.getLogger(__name__)


class PacketSniffer:
    """
    Captures network packets in real-time.
    Stores packet data for feature extraction and analysis.
    Requires root/administrator privileges.
    """

    def __init__(self, packet_buffer_size: int = 1000):
        """
        Initialize the packet sniffer.
        
        Args:
            packet_buffer_size: Maximum number of packets to keep in memory
            
        Raises:
            ValueError: If buffer size is invalid
        """
        if packet_buffer_size <= 0:
            raise ValueError("packet_buffer_size must be positive")
            
        self.packet_buffer: List[Dict] = []
        self.buffer_size = packet_buffer_size
        self.callbacks: List[Callable] = []
        self.packets_processed = 0
        logger.info(f"PacketSniffer initialized with buffer size: {packet_buffer_size}")

    def add_callback(self, callback: Callable) -> None:
        """
        Register a callback function to be called when packets are captured.
        
        Args:
            callback: Function that takes a packet dictionary as argument
            
        Raises:
            TypeError: If callback is not callable
        """
        if not callable(callback):
            raise TypeError("Callback must be callable")
        self.callbacks.append(callback)
        logger.debug(f"Callback registered: {callback.__name__}")

    def _parse_packet(self, packet) -> Dict:
        """
        Extract relevant information from a packet.
        
        Args:
            packet: Scapy packet object
            
        Returns:
            Dictionary with packet information
        """
        packet_info = {
            'src_ip': None,
            'dst_ip': None,
            'protocol': None,
            'is_syn': False,
            'size': len(packet),
        }

        try:
            # Extract IP information
            if packet.haslayer(IP):
                packet_info['src_ip'] = packet[IP].src
                packet_info['dst_ip'] = packet[IP].dst

            # Extract TCP information
            if packet.haslayer(TCP):
                packet_info['protocol'] = 'TCP'
                # Check if SYN flag is set (TCP flag value 2)
                if packet[TCP].flags == 2:
                    packet_info['is_syn'] = True

            # Extract UDP information
            elif packet.haslayer(UDP):
                packet_info['protocol'] = 'UDP'
                
        except Exception as e:
            logger.debug(f"Error parsing packet fields: {e}")

        return packet_info

    def _process_packet(self, packet) -> None:
        """
        Internal callback for packet processing.
        Called by scapy sniff() function.
        
        Args:
            packet: Scapy packet object
        """
        try:
            parsed_packet = self._parse_packet(packet)
            
            # Add to buffer (keep it bounded)
            self.packet_buffer.append(parsed_packet)
            if len(self.packet_buffer) > self.buffer_size:
                self.packet_buffer.pop(0)
            
            self.packets_processed += 1
            
            # Call registered callbacks
            for callback in self.callbacks:
                try:
                    callback(parsed_packet)
                except Exception as e:
                    logger.error(f"Error in callback: {e}")
                    
        except Exception as e:
            logger.error(f"Error processing packet: {e}")

    def start_sniffing(self, packet_count: int = 0, timeout: Optional[int] = None) -> None:
        """
        Start capturing packets.
        
        Args:
            packet_count: Number of packets to capture (0 = infinite)
            timeout: Timeout in seconds (None = infinite)
            
        Raises:
            PermissionError: If running without root/admin privileges
        """
        try:
            # Check for root privileges on Linux
            if os.name == 'posix' and os.geteuid() != 0:
                logger.warning("Running without root privileges - may have limited packet capture")
            
            logger.info("Starting packet sniffer...")
            logger.info(f"Timeout: {timeout}s, Packet count: {packet_count if packet_count > 0 else 'unlimited'}")
            
            # Sniff packets with minimal filtering for performance
            # Use store=False to not store packets in memory (we handle storage)
            sniff(
                prn=self._process_packet,
                count=packet_count if packet_count > 0 else 0,
                timeout=timeout,
                store=False
            )
            logger.info(f"Packet sniffing stopped. Total packets processed: {self.packets_processed}")
            
        except PermissionError:
            logger.error("Packet sniffing requires root/administrator privileges!")
            raise
        except KeyboardInterrupt:
            logger.info(f"Packet sniffing interrupted. Packets processed: {self.packets_processed}")
        except Exception as e:
            logger.error(f"Error during packet sniffing: {e}")
            raise

    def get_buffer(self) -> List[Dict]:
        """
        Get current packet buffer (copy).
        
        Returns:
            List copy of buffered packets
        """
        return self.packet_buffer.copy()

    def clear_buffer(self) -> None:
        """Clear the packet buffer."""
        self.packet_buffer.clear()

    def get_stats(self) -> Dict:
        """
        Get sniffer statistics.
        
        Returns:
            Dictionary with statistics
        """
        return {
            'total_packets_processed': self.packets_processed,
            'packets_in_buffer': len(self.packet_buffer),
            'buffer_capacity': self.buffer_size
        }
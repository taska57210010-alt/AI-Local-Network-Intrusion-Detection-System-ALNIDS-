"""
Attack Detection Module
Implements rule-based and AI-enhanced detection logic for identifying network attacks.

This module provides:
- Rule-based detection for common attack patterns (DDoS, SYN floods, port scans)
- AI-enhanced analysis using local LLM models
- Configurable detection thresholds
- Alert generation and tracking
"""

from typing import Dict, List, Optional
from dataclasses import dataclass
import logging
import requests

logger = logging.getLogger(__name__)


@dataclass
class Alert:
    """
    Represents a security alert.
    
    Attributes:
        alert_type: Type of attack detected (e.g., "DDoS", "Port Scan", "SYN Flood")
        severity: Alert severity level ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        message: Human-readable alert message
        triggered_features: Dictionary of features that triggered the alert
    """
    alert_type: str
    severity: str
    message: str
    triggered_features: Dict


class AttackDetector:
    """
    Network attack detection system with rule-based and AI-enhanced capabilities.
    
    Features:
    - Detects DDoS attacks, SYN floods, unusual traffic, and port scans
    - Configurable detection thresholds
    - AI integration for intelligent threat analysis
    - Alert tracking and retrieval
    """

    def __init__(self):
        """Initialize the detector with default thresholds and AI endpoint."""
        # Detection thresholds (can be tuned based on network baseline)
        self.thresholds = {
            'high_requests_per_sec': 100,      # Request rate threshold
            'syn_flood_packets': 50,           # SYN packet count threshold
            'syn_ratio_threshold': 0.3,        # SYN/TCP ratio threshold
            'unusual_unique_ips': 50,          # Unusual source IP count
            'port_scan_threshold': 100,        # Destination IP diversity threshold
        }
        
        # AI endpoint configuration (Ollama local API)
        self.ai_endpoint = "http://localhost:11434/api/generate"
        self.ai_model = "gemma:2b"
        
        # Alert storage
        self.alerts: List[Alert] = []

    def detect(self, features: Dict) -> List[Alert]:
        """
        Analyze network features using rule-based detection.
        
        Detects:
        - DDoS attacks: High request rate + many SYN packets
        - SYN floods: High SYN packet count with high SYN/TCP ratio
        - Unusual traffic: Abnormally high request rate
        - Port scanning: Many destination IPs from few source IPs
        
        Args:
            features: Dictionary of extracted network features, should contain:
                - requests_per_second (float)
                - tcp_syn_count (int)
                - tcp_packets (int)
                - unique_destination_ips (int)
                - unique_source_ips (int)
                
        Returns:
            List of Alert objects for triggered rules
        """
        self.alerts = []  # Reset alerts for this detection cycle

        # Rule 1: DDoS Detection (high requests per second + many SYN packets)
        if (features.get('requests_per_second', 0) > self.thresholds['high_requests_per_sec'] and
            features.get('tcp_syn_count', 0) > self.thresholds['syn_flood_packets']):
            self.alerts.append(Alert(
                alert_type="DDoS_ATTACK",
                severity="CRITICAL",
                message=f"Possible DDoS attack: {features.get('requests_per_second', 0):.2f} req/s, "
                        f"{features.get('tcp_syn_count', 0)} SYN packets",
                triggered_features={
                    'requests_per_second': features.get('requests_per_second', 0),
                    'tcp_syn_count': features.get('tcp_syn_count', 0)
                }
            ))

        # Rule 2: SYN Flood Detection
        elif features.get('tcp_syn_count', 0) > self.thresholds['syn_flood_packets']:
            # Calculate SYN ratio if we have TCP packets
            tcp_packets = features.get('tcp_packets', 0)
            if tcp_packets > 0:
                syn_ratio = features.get('tcp_syn_count', 0) / tcp_packets
                if syn_ratio > self.thresholds['syn_ratio_threshold']:
                    self.alerts.append(Alert(
                        alert_type="SYN_FLOOD",
                        severity="HIGH",
                        message=f"Possible SYN flood: {features.get('tcp_syn_count', 0)} SYN packets, "
                                f"ratio: {syn_ratio:.2%}",
                        triggered_features={
                            'tcp_syn_count': features.get('tcp_syn_count', 0),
                            'syn_ratio': syn_ratio
                        }
                    ))

        # Rule 3: Unusual Traffic Volume
        elif features.get('requests_per_second', 0) > self.thresholds['high_requests_per_sec']:
            self.alerts.append(Alert(
                alert_type="UNUSUAL_TRAFFIC",
                severity="MEDIUM",
                message=f"High traffic volume: {features.get('requests_per_second', 0):.2f} req/s",
                triggered_features={'requests_per_second': features.get('requests_per_second', 0)}
            ))

        # Rule 4: Port Scanning Detection
        if (features.get('unique_destination_ips', 0) > self.thresholds['port_scan_threshold'] and
            features.get('unique_source_ips', 0) < 10):
            self.alerts.append(Alert(
                alert_type="PORT_SCAN",
                severity="MEDIUM",
                message=f"Possible port scan: {features.get('unique_source_ips', 0)} sources "
                        f"scanning {features.get('unique_destination_ips', 0)} destinations",
                triggered_features={
                    'unique_source_ips': features.get('unique_source_ips', 0),
                    'unique_destination_ips': features.get('unique_destination_ips', 0)
                }
            ))

        return self.alerts

    def get_alerts(self) -> List[Alert]:
        """
        Get the latest detected alerts.
        
        Returns:
            List copy of current alerts
        """
        return self.alerts.copy()

    def set_threshold(self, threshold_name: str, value: float) -> bool:
        """
        Update a detection threshold.
        
        Args:
            threshold_name: Name of the threshold to update
            value: New threshold value
            
        Returns:
            True if threshold was updated, False if threshold not found
        """
        if threshold_name in self.thresholds:
            self.thresholds[threshold_name] = value
            logger.info(f"Updated threshold {threshold_name} to {value}")
            return True
        else:
            logger.warning(f"Unknown threshold: {threshold_name}")
            return False

    def get_thresholds(self) -> Dict:
        """
        Get current detection thresholds.
        
        Returns:
            Dictionary copy of current thresholds
        """
        return self.thresholds.copy()

    def ai_analyze(self, features: Dict) -> str:
        """
        Perform AI-enhanced threat analysis using local LLM.
        
        Sends network features to a local Ollama API instance running Gemma model
        for intelligent threat analysis and recommendations.
        
        Args:
            features: Dictionary of network features to analyze
            
        Returns:
            AI analysis result as string, or error message if API unavailable
        """
        try:
            # Format features as human-readable text for the AI
            features_text = self._format_features_for_ai(features)
            
            # Prepare prompt for the AI model
            prompt = f"""Analyze the following network security features and provide threat assessment:

Network Features:
{features_text}

Provide a brief threat assessment including:
1. Detected threat level (Low/Medium/High/Critical)
2. Likely attack types if any
3. Recommended actions"""
            
            # Prepare JSON payload for Ollama API
            payload = {
                "model": self.ai_model,
                "prompt": prompt,
                "stream": False
            }
            
            # Send request to local Ollama API
            response = requests.post(
                self.ai_endpoint,
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                return result.get('response', 'No response from AI model')
            else:
                return f"AI API error (status {response.status_code})"
                
        except requests.exceptions.ConnectionError:
            logger.warning(f"Could not connect to AI endpoint: {self.ai_endpoint}")
            return "AI service unavailable (local Ollama not running)"
        except requests.exceptions.Timeout:
            logger.warning("AI API request timed out")
            return "AI analysis timed out"
        except Exception as e:
            logger.error(f"AI analysis failed: {str(e)}")
            return f"AI analysis error: {str(e)}"

    def _format_features_for_ai(self, features: Dict) -> str:
        """
        Format network features as readable text for AI analysis.
        
        Args:
            features: Network feature dictionary
            
        Returns:
            Formatted string representation of features
        """
        formatted = []
        for key, value in features.items():
            # Convert snake_case to readable text
            readable_key = key.replace('_', ' ').title()
            formatted.append(f"- {readable_key}: {value}")
        return "\n".join(formatted)

    def detect_with_ai(self, features: Dict) -> Dict:
        """
        Perform combined rule-based and AI-enhanced detection.
        
        Runs both traditional rule-based detection and AI analysis,
        returning results from both approaches for comprehensive threat assessment.
        
        Args:
            features: Dictionary of network features to analyze
            
        Returns:
            Dictionary containing:
                - rule_alerts: List of Alert objects from rule-based detection
                - ai_result: String with AI analysis results
        """
        # Run rule-based detection
        rule_alerts = self.detect(features)
        
        # Run AI analysis
        ai_result = self.ai_analyze(features)
        
        return {
            'rule_alerts': rule_alerts,
            'ai_result': ai_result
        }

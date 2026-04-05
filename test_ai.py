#!/usr/bin/env python3
"""
Test script to verify AI integration is working.
Tests the detector's AI analysis capabilities.
"""

import sys
import time
from detector import AttackDetector


def test_ai_connection():
    """Test if we can connect to the AI service."""
    detector = AttackDetector()
    
    print("=" * 70)
    print("🤖 AI Service Connection Test")
    print("=" * 70)
    print(f"\nAI Endpoint: {detector.ai_endpoint}")
    print(f"AI Model: {detector.ai_model}")
    print("\nTesting connection...\n")
    
    # Test with simple features
    test_features = {
        'packet_count': 100,
        'requests_per_second': 50.0,
        'unique_source_ips': 5,
        'unique_destination_ips': 10,
        'tcp_syn_count': 25,
        'tcp_packets': 80,
        'udp_packets': 20,
        'average_packet_size': 128.5,
    }
    
    print("Sending test request to AI...\n")
    start_time = time.time()
    result = detector.ai_analyze(test_features)
    elapsed = time.time() - start_time
    
    print(f"Response time: {elapsed:.2f}s\n")
    print("AI Response:")
    print("-" * 70)
    print(result)
    print("-" * 70)
    
    # Check if we got a real response
    if "unavailable" in result.lower() or "error" in result.lower():
        print("\n❌ AI service is NOT available")
        print("\n✅ Next Steps:")
        print("   1. Install Ollama: https://ollama.ai")
        print("   2. Run: ollama pull gemma:2b")
        print("   3. Run: ollama serve")
        print("   4. Then run this test again")
        return False
    else:
        print("\n✅ AI service is working!")
        return True


def test_combined_detection():
    """Test rule-based + AI detection together."""
    detector = AttackDetector()
    
    print("\n" + "=" * 70)
    print("🛡️ Combined Detection Test (Rules + AI)")
    print("=" * 70)
    
    # Simulate DDoS attack features
    attack_features = {
        'packet_count': 5000,
        'requests_per_second': 250.0,
        'unique_source_ips': 3,
        'unique_destination_ips': 1,
        'tcp_syn_count': 150,
        'tcp_packets': 4500,
        'udp_packets': 500,
        'average_packet_size': 64.0,
    }
    
    print("\nSimulating DDoS attack scenario...\n")
    
    # Get combined results
    results = detector.detect_with_ai(attack_features)
    
    # Display rule-based alerts
    print("📋 Rule-Based Detections:")
    print("-" * 70)
    if results['rule_alerts']:
        for alert in results['rule_alerts']:
            print(f"  🚨 {alert.alert_type} ({alert.severity})")
            print(f"     Message: {alert.message}")
    else:
        print("  ✅ No rule-based alerts")
    
    # Display AI analysis
    print("\n🤖 AI Analysis:")
    print("-" * 70)
    print(results['ai_result'])
    print("-" * 70)
    
    return True


def main():
    """Run all tests."""
    print("\n")
    
    try:
        ai_working = test_ai_connection()
        test_combined_detection()
        
        print("\n" + "=" * 70)
        print("✅ Test Complete")
        print("=" * 70)
        print("\nTo use AI in the dashboard:")
        print("  1. Run: ollama serve  (in a separate terminal)")
        print("  2. Run: streamlit run dashboard.py")
        print("  3. Alerts will now include AI analysis\n")
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()

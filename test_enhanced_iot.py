#!/usr/bin/env python3
"""
Quick test for IoT Edge Agent CLI with enhanced scoring
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).resolve().parent
sys.path.insert(0, str(project_root))

from agents.iot_edge_agent import IoTEdgeAgent, _generate_mock_iot_target

def test_enhanced_scoring():
    """Test the enhanced 10-parameter scoring system"""
    print("Testing Enhanced IoT Edge Agent (10 parameters, 0-100 scale)")
    
    # Create a mock target with all 10 parameters
    target = _generate_mock_iot_target("test-device")
    
    # Initialize agent with region
    agent = IoTEdgeAgent(region="US")
    
    # Run scan
    assessment = agent.scan({"scan_targets": [target]})
    
    # Display results
    print("\nResults:")
    for item in assessment.get("rated_assets", []):
        print(f"Asset: {item['asset']}")
        print(f"Score: {item['score_100']}/100 ({item['verdict']})")
        print(f"Priority: {item['priority_level']}")
        print(f"Region: {item['region']}")
        print("\nParameter Breakdown:")
        for param, data in item.get("parameter_scores", {}).items():
            if data["score"] is not None:
                print(f"  {param:25s}: {data['score']:.2f} (weight: {data['effective_weight']:.2f})")
            else:
                print(f"  {param:25s}: N/A")
    
    return assessment

if __name__ == "__main__":
    test_enhanced_scoring()
#!/usr/bin/env python3
"""
Test script for subdomain discovery and scanning
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).resolve().parent
sys.path.insert(0, str(project_root))

from agents.iot_edge_agent import IoTEdgeAgent, _is_domain_name, _discover_domain_targets

def test_google_scan():
    """Test scanning google.com with subdomain discovery"""
    domain = "google.com"
    
    print(f"Testing domain detection for '{domain}': {_is_domain_name(domain)}")
    
    if _is_domain_name(domain):
        print(f"\nDiscovering subdomains for {domain}...")
        targets = _discover_domain_targets(domain)
        
        print(f"Found {len(targets)} targets:")
        for target in targets:
            print(f"  - {target['asset']}")
        
        print(f"\nRunning PQC assessment on discovered targets...")
        agent = IoTEdgeAgent()
        assessment = agent.scan({"scan_targets": targets})
        agent.save_local()
        
        print("\nResults:")
        for item in assessment.get("rated_assets", []):
            print(f"  #{item['priority_rank']} | {item['asset']} - {item['rating']}/10 ({item['verdict']})")
    
    return assessment

if __name__ == "__main__":
    test_google_scan()
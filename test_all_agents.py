import json
import logging
from agents.web_api_agent import WebApiAgent
from agents.cloud_storage_agent import CloudStorageAgent
from agents.iot_edge_agent import IoTEdgeAgent
from agents.ai_crypto_security_agent import AlgorithmsNetworkAgent

logging.basicConfig(level=logging.ERROR)

def test_agent(AgentClass, name):
    print(f"\n{'='*70}\n  Testing: {name}\n{'='*70}")
    try:
        assessment = AgentClass.scan_mock_data()
        all_ok = True
        total_assets = len(assessment.get("rated_assets", []))
        total_recs = 0
        for asset in assessment.get("rated_assets", []):
            recs = asset.get("migration_recommendations", [])
            total_recs += len(recs)
            params = asset.get("parameter_scores", {})
            for p, d in params.items():
                if d.get("score") is None:
                    print(f"    [!] Failed: {asset['asset']} has None score for {p}")
                    all_ok = False
        if total_recs == 0:
            print(f"    [!] Failed: No recommendations found for {name}")
            all_ok = False
            
        if all_ok:
            print(f"  PASSED - {total_assets} assets, {len(assessment['rated_assets'][0]['parameter_scores'])} params discovered for first asset. Zero N/A entries.")
            return True
        return False
    except Exception as e:
        print(f"    [!] Error testing {name}: {e}")
        return False

def main():
    results = []
    results.append(("Web API Agent", test_agent(WebApiAgent, "Web API Agent")))
    results.append(("Cloud Storage Agent", test_agent(CloudStorageAgent, "Cloud Storage Agent")))
    results.append(("IoT Edge Agent", test_agent(IoTEdgeAgent, "IoT Edge Agent")))
    results.append(("Crypto/Network Agent", test_agent(AlgorithmsNetworkAgent, "Crypto/Network Agent")))

    print(f"\n{'='*70}\n  SUMMARY\n{'='*70}")
    for name, passed in results:
        status = "PASSED" if passed else "FAILED"
        print(f"  {name:<30} {status}")
    print(f"{'='*70}\n")

if __name__ == "__main__":
    main()

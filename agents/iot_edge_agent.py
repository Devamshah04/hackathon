"""
IoT & Edge Devices Agent

Full implementation using Strands SDK + AWS Bedrock (Claude 3.5 Sonnet).
Scans IoT infrastructure for quantum-vulnerable cryptography across 5 parameters,
produces 1–10 ratings per asset, and ranks them by migration priority.

Architecture:
  1. Loads target data (mock or real)
  2. Runs scanner tools deterministically for raw scores
  3. Feeds findings to Strands AI agent for analysis + recommendations
  4. Scoring engine computes weighted rating (1–10)
  5. Learning store records results for RL-style improvement
  6. Outputs priority-ranked assessment
"""

from __future__ import annotations

import sys as _sys

# Fix Windows console encoding for box-drawing characters
if _sys.platform == "win32":
    try:
        _sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        _sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import json
import logging
import os
import sys
from pathlib import Path

# Add project root to sys.path so direct execution works
_current_dir = Path(__file__).resolve().parent
_project_root = _current_dir.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from core.base_agent import BaseAgent
from core.learning_store import LearningStore
# Enhanced scoring system
from core.enhanced_scoring_engine import EnhancedScoringEngine
from core.enhanced_region_standards import get_enhanced_region_profile

# Scanner tools (enhanced to 10 parameters)
from tools.iot_scanner import scan_iot_device
from tools.keymgmt_scanner import scan_key_management
from tools.quantum_readiness_scanner import scan_quantum_readiness
# Additional enhanced scanners for IoT
from tools.enhanced_scanners import (
    scan_certificate_security,
    scan_data_at_rest,
    scan_regulatory_compliance
)

logger = logging.getLogger("pqc.iot_edge_agent")

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"


class IoTEdgeAgent(BaseAgent):
    """
    Enhanced agent for scanning IoT & Edge infrastructure with regional compliance.

    Evaluates 10 parameters per asset:
      1. Firmware Signing       (weight: 15%)
      2. Device Longevity       (weight: 12%)
      3. OTA Security           (weight: 10%)
      4. Key Management         (weight: 12%)
      5. Quantum Readiness      (weight: 8%)
      6. Hardware Security      (weight: 10%)
      7. Communication Protocol (weight: 8%)
      8. Certificate Security   (weight: 8%)
      9. Data at Rest           (weight: 9%)
      10. Regulatory Compliance (weight: 8%)

    Produces a 0–100 rating with regional weighting and priority-ranked migration list.
    """

    def __init__(self, region: str = "US"):
        super().__init__(agent_name="iot_edge_agent")
        self.region = region.upper()
        self.region_profile = get_enhanced_region_profile(self.region)
        self.scoring_engine = EnhancedScoringEngine(domain="iot_edge", region=self.region)
        self.learning_store = LearningStore(agent_name="iot_edge_agent")
        self._strands_agent = None

    # ── Strands AI Agent (lazy init) ────────────────────────────────────────

    def _get_strands_agent(self):
        """
        Initialize the Strands AI agent with Bedrock.
        Falls back to local-only mode if Bedrock is unavailable.
        """
        if self._strands_agent is not None:
            return self._strands_agent

        if hasattr(self, '_strands_agent_failed'):
            return None

        try:
            from strands import Agent
            from strands.models.bedrock import BedrockModel

            model = BedrockModel(
                model_id=os.getenv(
                    "BEDROCK_MODEL_ID",
                    "anthropic.claude-3-5-sonnet-20241022-v2:0",
                ),
                region_name=os.getenv("AWS_REGION", "us-east-1"),
            )

            # Build learning context for the system prompt
            learning_ctx = self.learning_store.build_learning_context()

            system_prompt = f"""You are a Post-Quantum Cryptography (PQC) security analyst AI agent.

Your job is to analyze IoT & Edge infrastructure for quantum-vulnerable cryptographic
implementations and recommend region-specific PQC replacements.

Regional Context: {self.region} ({self.region_profile['name']})
Regulatory Body: {self.region_profile['body_full']}
Standards: {', '.join(self.region_profile['standards'])}
Compliance Deadline: {self.region_profile['deadline']}

For each asset you analyze, you will receive scan results from 10 security parameters:
1. Firmware Signing — Algorithms used to sign firmware (e.g. RSA, LMS, XMSS)
2. Device Longevity — Expected lifespan relative to the quantum threat year (2030)
3. OTA Security — Secure update channels and their signing algorithms
4. Key Management — Storage, rotation, algorithms for device keys
5. Quantum Readiness — PQC deployment, hybrid mode, crypto agility
6. Hardware Security — Hardware Root of Trust, secure enclaves, TPM
7. Communication Protocol — Device-to-cloud communication encryption
8. Certificate Security — Device certificates and PKI infrastructure
9. Data at Rest — Local storage encryption on the device
10. Regulatory Compliance — {self.region_profile['body']} requirements, documentation

Your analysis should:
- Identify the most critical vulnerabilities, particularly for long-lived devices
- Explain WHY each finding is a quantum risk (reference Shor's algorithm, Harvest-Now-Decrypt-Later)
- Provide specific, actionable migration recommendations
- Reference NIST standards (NIST SP 800-208 for stateful hash-based signatures)
- Consider that field-deployed IoT devices often cannot be easily updated
- Provide 0-100 scoring context with regional priorities

{learning_ctx}
"""

            self._strands_agent = Agent(
                model=model,
                system_prompt=system_prompt,
                tools=[
                    scan_iot_device,
                    scan_key_management,
                    scan_quantum_readiness,
                ],
            )
            logger.info("Strands AI agent initialized with Bedrock")
            return self._strands_agent

        except Exception as e:
            logger.warning(f"Could not initialize Strands agent: {e}")
            logger.info("Running in local-only mode (deterministic scoring, no AI analysis)")
            self._strands_agent_failed = True
            return None

    # ── Deterministic Tool Scanning ─────────────────────────────────────────

    def _scan_asset_tools(self, target: dict) -> dict:
        """
        Run all 10 scanner tools on a single IoT asset. Returns raw scores.
        This runs locally — no LLM needed.
        """
        scores = {}
        all_findings = []

        asset = target.get("asset", "unknown")

        # 1-3. IoT Scanner (Firmware, Longevity, OTA)
        firmware_metadata = target.get("firmware_metadata", {})
        if firmware_metadata and firmware_metadata.get("firmware_version", "unknown") != "unknown":
            iot_result = json.loads(scan_iot_device(firmware_metadata=json.dumps(firmware_metadata)))
            
            iot_sub_scores = iot_result.get("sub_scores", {})
            
            # Firmware Signing
            scores["firmware_signing"] = (
                iot_sub_scores.get("firmware_signing", 0.0),
                f"Signed with {firmware_metadata.get('signing_algorithm', 'unknown')}"
            )
            
            # Device Longevity
            scores["device_longevity"] = (
                iot_sub_scores.get("device_longevity", 0.0),
                f"Lifespan ends {iot_result.get('longevity_details', {}).get('expected_end_of_life', '?')}"
            )
            
            # OTA Security
            scores["ota_security"] = (
                iot_sub_scores.get("ota_security", 0.0),
                f"OTA algorithm: {firmware_metadata.get('ota_signing', 'none')}"
            )
            
            all_findings.extend([
                {"parameter": f["component"], "asset": asset, **f}
                for f in iot_result.get("findings", [])
            ])

        # 4. Key Management
        keymgmt_config = target.get("key_management", {})
        if keymgmt_config and keymgmt_config.get("storage_type", "unknown") != "unknown":
            km_result = json.loads(scan_key_management(config=json.dumps(keymgmt_config)))
            scores["key_management"] = (
                km_result.get("score", 0.0),
                f"{keymgmt_config.get('storage_type', '?')} storage, {keymgmt_config.get('rotation_policy', '?')}"
            )
            all_findings.extend([
                {"parameter": "key_management", "asset": asset, **f}
                for f in km_result.get("findings", [])
            ])

        # 5. Quantum Readiness
        qr_config = target.get("quantum_readiness", {})
        if qr_config and (qr_config.get("crypto_agile") is True or qr_config.get("pqc_algorithms_deployed")):
            qr_result = json.loads(scan_quantum_readiness(config=json.dumps(qr_config)))
            scores["quantum_readiness"] = (
                qr_result.get("score", 0.0),
                "PQC deployed" if qr_config.get("pqc_algorithms_deployed") else "No PQC readiness"
            )
            all_findings.extend([
                {"parameter": "quantum_readiness", "asset": asset, **f}
                for f in qr_result.get("findings", [])
            ])

        # 6. Hardware Security
        hw_config = target.get("hardware_security", firmware_metadata)
        if hw_config and hw_config.get("hardware_root_of_trust") is not None:
            hw_score = 0.8 if hw_config.get("hardware_root_of_trust") else 0.2
            scores["hardware_security"] = (
                hw_score,
                f"HRoT: {hw_config.get('hardware_root_of_trust', False)}, TPM: {hw_config.get('tpm_enabled', False)}"
            )

        # 7. Communication Protocol
        comm_config = target.get("communication_protocol", {})
        if comm_config and comm_config.get("protocol"):
            # Simple scoring based on protocol security
            protocol = comm_config.get("protocol", "unknown")
            if "TLS" in protocol.upper() or "DTLS" in protocol.upper():
                comm_score = 0.7
            elif "MQTT" in protocol.upper() or "COAP" in protocol.upper():
                comm_score = 0.5
            else:
                comm_score = 0.2
            scores["communication_protocol"] = (
                comm_score,
                f"Protocol: {protocol}, Encryption: {comm_config.get('encryption', 'unknown')}"
            )

        # 8. Certificate Security
        cert_config = target.get("certificate_security", {})
        if cert_config and cert_config.get("cert_algorithm"):
            cert_result = json.loads(scan_certificate_security(config=json.dumps(cert_config)))
            scores["certificate_security"] = (
                cert_result.get("score", 0.0),
                f"Cert: {cert_config.get('cert_algorithm', '?')}, {cert_config.get('validity_years', '?')}y validity"
            )
            all_findings.extend([
                {"parameter": "certificate_security", "asset": asset, **f}
                for f in cert_result.get("findings", [])
            ])

        # 9. Data at Rest
        data_rest_config = target.get("data_at_rest", {})
        if data_rest_config and data_rest_config.get("encryption_algorithm"):
            data_result = json.loads(scan_data_at_rest(config=json.dumps(data_rest_config)))
            scores["data_at_rest"] = (
                data_result.get("score", 0.0),
                f"Storage: {data_rest_config.get('encryption_algorithm', '?')}"
            )
            all_findings.extend([
                {"parameter": "data_at_rest", "asset": asset, **f}
                for f in data_result.get("findings", [])
            ])

        # 10. Regulatory Compliance
        compliance_config = target.get("regulatory_compliance", {})
        if compliance_config and (compliance_config.get("frameworks") or compliance_config.get("pqc_migration_plan")):
            compliance_result = json.loads(scan_regulatory_compliance(config=json.dumps(compliance_config)))
            scores["regulatory_compliance"] = (
                compliance_result.get("score", 0.0),
                f"Frameworks: {len(compliance_config.get('frameworks', []))}, PQC plan: {compliance_config.get('pqc_migration_plan', False)}"
            )
            all_findings.extend([
                {"parameter": "regulatory_compliance", "asset": asset, **f}
                for f in compliance_result.get("findings", [])
            ])

        return {
            "asset": asset,
            "scores": scores,
            "findings": all_findings,
        }

    # ── AI Analysis Layer ───────────────────────────────────────────────────

    def _get_ai_analysis(self, asset: str, scores: dict, findings: list) -> list[str]:
        """
        Use Strands AI agent to generate human-readable analysis and recommendations.
        Falls back to rule-based recommendations if Bedrock unavailable.
        """
        agent = self._get_strands_agent()

        if agent is None:
            # Fallback: deterministic recommendations
            return self._generate_deterministic_recommendations(scores, findings)

        try:
            prompt = f"""Analyze the following PQC scan results for IoT asset "{asset}":

Parameter Scores (0.0 = insecure, 1.0 = quantum-safe):
{json.dumps({k: {"score": v[0], "details": v[1]} for k, v in scores.items()}, indent=2)}

Findings:
{json.dumps(findings, indent=2)}

Provide:
1. A brief overall assessment (2-3 sentences), specifically evaluating the longevity risk
2. Top 3 prioritized migration recommendations with NIST standards
3. Estimated migration complexity (Low/Medium/High)
"""
            response = agent(prompt)
            # Extract text from response
            if hasattr(response, "message"):
                text = response.message.get("content", [{}])[0].get("text", "")
            else:
                text = str(response)

            return [text] if text else self._generate_deterministic_recommendations(scores, findings)

        except Exception as e:
            logger.info(f"Using local deterministic recommendations for {asset} (AI bypassed: {e})")
            return self._generate_deterministic_recommendations(scores, findings)

    def _generate_deterministic_recommendations(self, scores: dict, findings: list) -> list[str]:
        """Generate rule-based recommendations when AI is unavailable."""
        recommendations = []

        for param_name, (score, details) in scores.items():

            if score < 0.3:
                if param_name == "firmware_signing":
                    recommendations.append(
                        "CRITICAL: Migrate firmware signing from RSA/ECDSA to stateful hash-based "
                        "signatures (LMS/XMSS) per NIST SP 800-208."
                    )
                elif param_name == "device_longevity":
                    recommendations.append(
                        "CRITICAL: Device lifespan extends past projected quantum threat year (2030). "
                        "Immediate hardware or software refresh planning required."
                    )
                elif param_name == "ota_security":
                    recommendations.append(
                        "HIGH: Upgrade OTA update authentication to use ML-DSA to secure the supply chain."
                    )
                elif param_name == "key_management":
                    recommendations.append(
                        "CRITICAL: Move embedded keys to a Hardware Root of Trust or secure enclave."
                    )
                elif param_name == "quantum_readiness":
                    recommendations.append(
                        "HIGH: No PQC awareness on device firmware. Implement crypto agility."
                    )
            elif score < 0.6:
                recommendations.append(
                    f"MEDIUM: Improve {param_name} ({details}). "
                    f"Score {score:.1f}/1.0 indicates partial quantum exposure."
                )

        if not recommendations:
            recommendations.append(
                "IoT Asset has reasonable quantum posture. Ensure physical security is maintained."
            )

        return recommendations

    # ── Main Scan Method ────────────────────────────────────────────────────

    def scan(self, target: dict) -> dict:
        """
        Scan IoT targets for quantum-vulnerable crypto.

        Accepts either:
          - A single target dict with asset config
          - A dict with "scan_targets" key containing a list of targets

        Returns:
            Full assessment dict with rated & priority-ranked assets.
        """
        # Handle both single target and multi-target input
        if "scan_targets" in target:
            targets = target["scan_targets"]
        else:
            targets = [target]

        logger.info(f"Scanning {len(targets)} IoT assets...")

        ratings = []

        for i, t in enumerate(targets, 1):
            asset = t.get("asset", f"asset-{i}")
            logger.info(f"  [{i}/{len(targets)}] Scanning {asset}...")

            # Step 1: Run deterministic tools
            scan_result = self._scan_asset_tools(t)

            # Step 2: Get AI analysis / recommendations
            recommendations = self._get_ai_analysis(
                asset=asset,
                scores=scan_result["scores"],
                findings=scan_result["findings"],
            )

            # Step 3: Compute weighted score → 1–10 rating
            asset_rating = self.scoring_engine.score_asset_dynamic(
                asset=asset,
                scores=scan_result["scores"],
                findings=scan_result["findings"],
                recommendations=recommendations,
            )

            ratings.append(asset_rating)

            # Step 4: Record in learning store
            self.learning_store.record_scan(
                asset=asset,
                rating=asset_rating.score_100,
                parameter_scores={
                    p.name: p.score for p in asset_rating.parameter_scores
                },
                findings_summary=f"{len(scan_result['findings'])} findings, "
                                 f"rating {asset_rating.score_100}/100 ({asset_rating.verdict})",
                run_id=self.run_id,
            )

            # Also add to base agent findings
            for finding in scan_result["findings"]:
                self.findings.append(finding)

            logger.info(
                f"  [{i}/{len(targets)}] {asset}: "
                f"Rating {asset_rating.score_100}/100 — {asset_rating.verdict}"
            )

        # Step 5: Priority ranking (worst first)
        ranked = self.scoring_engine.rank_assets(ratings)
        self.asset_ratings = ranked

        # Log summary table
        summary = self.scoring_engine.summary_table(ranked)
        logger.info(f"\n{'='*72}\nPQC Migration Priority Ranking — IoT & Edge\n{'='*72}\n{summary}\n{'='*72}")

        return self.build_assessment()

    # ── Convenience: Load & Scan Mock Data ──────────────────────────────────

    @classmethod
    def scan_mock_data(cls, mock_file: str | None = None) -> dict:
        """
        Convenience method to load mock data and run a full scan.

        Args:
            mock_file: Path to mock JSON file. Defaults to data/mock_iot_targets.json

        Returns:
            Full assessment with rated assets.
        """
        if mock_file is None:
            mock_file = str(_DATA_DIR / "mock_iot_targets.json")

        with open(mock_file, "r") as f:
            targets = json.load(f)

        agent = cls()
        assessment = agent.scan(targets)
        agent.save_local()

        print(f"\n[*] Learning Store: {agent.learning_store.summary()}")
        return assessment


# ── Interactive CLI Mode ──────────────────────────────────────────────────

def _generate_mock_iot_target(device_name: str) -> dict:
    """Generate a plausible mock IoT target for a given device name."""
    return {
        "asset": device_name,
        "description": f"IoT device: {device_name}",
        "firmware_metadata": {
            "device_name": device_name,
            "firmware_version": "1.0.0",
            "signing_algorithm": "RSA-2048",
            "manufacture_year": 2022,
            "expected_lifespan_years": 10,
            "ota_enabled": True,
            "ota_signing": "ECDSA-P256",
            "hardware_root_of_trust": False,
            "tpm_enabled": False
        },
        "key_management": {
            "storage_type": "flash",
            "rotation_policy": "no_rotation",
            "key_algorithm": "RSA-2048",
            "key_count": 1,
            "separation_of_duties": False,
            "audit_logging": False,
            "backup_exists": False
        },
        "quantum_readiness": {
            "pqc_algorithms_deployed": [],
            "hybrid_mode_enabled": False,
            "crypto_agile": False,
            "migration_plan_exists": False,
            "migration_plan_timeline": "",
            "pqc_testing_done": False,
            "library_supports_pqc": False
        },
        "hardware_security": {
            "hardware_root_of_trust": False,
            "tpm_enabled": False,
            "secure_enclave": False,
            "hardware_crypto_acceleration": False
        },
        "communication_protocol": {
            "protocol": "MQTT",
            "encryption": "TLS 1.2",
            "authentication": "username_password",
            "message_integrity": True
        },
        "certificate_security": {
            "cert_algorithm": "RSA-2048",
            "validity_years": 3,
            "chain_depth": 3,
            "ca_trusted": True
        },
        "data_at_rest": {
            "encryption_algorithm": "AES-128",
            "key_storage": "flash",
            "key_rotation_days": 0
        },
        "regulatory_compliance": {
            "frameworks": [],
            "pqc_migration_plan": False,
            "audit_logging": False,
            "crypto_documentation": False
        }
    }

def _is_domain_name(target: str) -> bool:
    """Check if target looks like a domain name."""
    import re
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z]{2,}$'
    return bool(re.match(domain_pattern, target))

def _discover_domain_targets(domain: str) -> list[dict]:
    """Discover subdomains and create assessment targets."""
    from tools.subdomain_discovery import discover_subdomains_for_assessment
    
    logger.info(f"Discovering subdomains for {domain}...")
    targets = discover_subdomains_for_assessment(domain, max_subdomains=5)
    
    # Convert web targets to IoT-style targets for assessment
    iot_targets = []
    for target in targets:
        iot_target = {
            "asset": target["asset"],
            "description": f"Domain endpoint: {target['asset']}",
            "firmware_metadata": {
                "device_name": target["asset"],
                "firmware_version": "web-service",
                "signing_algorithm": target.get("tls_config", {}).get("key_exchange", "RSA-2048"),
                "manufacture_year": 2020,
                "expected_lifespan_years": 15,  # Web services often run longer
                "ota_enabled": True,
                "ota_signing": "RSA-2048",
                "hardware_root_of_trust": False,
                "tpm_enabled": False
            },
            "key_management": target.get("key_management", {}),
            "quantum_readiness": target.get("quantum_readiness", {}),
            "hardware_security": {
                "hardware_root_of_trust": False,
                "tpm_enabled": False,
                "secure_enclave": False,
                "hardware_crypto_acceleration": True  # Assume cloud infrastructure
            },
            "communication_protocol": {
                "protocol": "HTTPS",
                "encryption": target.get("tls_config", {}).get("tls_version", "TLS 1.2"),
                "authentication": "certificate",
                "message_integrity": True
            },
            "certificate_security": target.get("certificate_security", {
                "cert_algorithm": "RSA-2048",
                "validity_years": 1,
                "chain_depth": 3,
                "ca_trusted": True
            }),
            "data_at_rest": target.get("data_at_rest", {
                "encryption_algorithm": "AES-256",
                "key_storage": "cloud_kms",
                "key_rotation_days": 90
            }),
            "regulatory_compliance": target.get("regulatory_compliance", {
                "frameworks": [],
                "pqc_migration_plan": False,
                "audit_logging": True,
                "crypto_documentation": False
            })
        }
        iot_targets.append(iot_target)
    
    return iot_targets


def run_interactive_cli():
    import time

    BANNER = """
  =====================================================================
      PQC IoT & EDGE AGENT  v1.0  -  Strands SDK + Amazon Bedrock      
      Post-Quantum Cryptography Migration Scanner — IoT & Edge         
  =====================================================================
   Standards:  NIST SP 800-208  ·  FIPS 203/204/205  ·  CNSA 2.0       
               Stateful Hash-Based Signatures (LMS / XMSS)             
  =====================================================================
   Commands:                                                           
     scan        - Full scan + report for a device or mock dataset     
     list        - List available mock datasets                        
     help        - Show command reference                              
     exit        - Quit the agent                                      
  =====================================================================
"""
    MOCK_DATASETS = ['AcmeCorp-IoT']

    print(BANNER)
    print("⚙ Initialising Strands agent with Amazon Bedrock...\n")
    time.sleep(1)

    print("🤖 PQC IoT & Edge Agent - Interactive Mode")
    print(f"Available mock datasets: {MOCK_DATASETS}")
    print("Type 'help' for suggested queries, 'exit' to quit.\n")

    while True:
        try:
            cmd_line = input("You: ").strip()
            if not cmd_line:
                continue

            parts = cmd_line.split()
            cmd = parts[0].lower()
            args = parts[1:]

            if cmd in ("exit", "quit"):
                print("Exiting PQC IoT Agent...")
                break
            elif cmd == "help":
                print("Commands:")
                print("  scan mock              - Full scan on predefined AcmeCorp IoT mock dataset")
                print("  scan [domain.com]      - Scan a domain and its subdomains for PQC vulnerabilities")
                print("  scan [device-name]     - Scan a custom device with a default insecure profile")
                print("  list                   - List available mock datasets")
            elif cmd == "list":
                print(f"Available mock datasets: {MOCK_DATASETS}")
            elif cmd == "scan":
                agent = IoTEdgeAgent()
                target_arg = args[0] if args else "mock"
                assessment = None

                if target_arg == "mock" or target_arg in MOCK_DATASETS:
                    print("\nRunning scan on AcmeCorp IoT mock data...")
                    assessment = IoTEdgeAgent.scan_mock_data()
                else:
                    if _is_domain_name(target_arg):
                        print(f"\nScanning domain and subdomains: {target_arg}...")
                        domain_targets = _discover_domain_targets(target_arg)
                        targets = {"scan_targets": domain_targets}
                    else:
                        print(f"\nScanning IoT device profile: {target_arg}...")
                        targets = {"scan_targets": [_generate_mock_iot_target(target_arg)]}
                    
                    assessment = agent.scan(targets)
                    agent.save_local()

                if assessment:
                    print("\nRESULTS:")
                    for item in assessment.get("rated_assets", []):
                        print(f"\n{'-' * 60}")
                        print(f"  #{item['priority_rank']} │ {item['asset']}")
                        print(f"     Rating:  {item['score_100']}/100 — {item['verdict']}")
                        print(f"     Priority: {item['priority_level']}")
                        print(f"     Action:  {item['action']}")
                        print(f"     Score:   {item['weighted_score']:.4f}")
                        print(f"     Region:  {item.get('region', 'US')}")
                        print(f"     Params ({len(item.get('parameter_scores', {}))} discovered):")
                        for param, data in item.get("parameter_scores", {}).items():
                            filled = int(data["score"] * 20)
                            bar = chr(9608) * filled + chr(9617) * (20 - filled)
                            print(f"       {param:25s} {bar} {data['score']:.2f} (weight: {data.get('effective_weight', 0):.2f})")

                    # Show recommendations
                    recs = item.get("migration_recommendations", [])
                    if recs:
                        print(f"\n     [>] Recommendations:")
                        for rec in recs[:3]:
                            display = rec[:120] + "..." if len(rec) > 120 else rec
                            print(f"       -> {display}")

                    # Automatically export PDF report
                    try:
                        from core.pdf_report_generator import PdfReportGenerator
                        generator = PdfReportGenerator()
                        pdf_path = generator.generate_report(assessment, domain_name=f"IoT_{target_arg}")
                        print(f"\n[*] Complete Risk Assessment PDF exported to: {pdf_path}")
                    except Exception as e:
                        print(f"\n[!] Failed to generate PDF Report: {e}")

            else:
                print(f"Unrecognized command: {cmd}. Type 'help' for options.")

        except KeyboardInterrupt:
            print("\nExiting...")
            break
        except Exception as e:
            print(f"Error: {e}")


if __name__ == "__main__":
    run_interactive_cli()

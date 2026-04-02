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
from core.scoring_engine import ScoringEngine
from core.learning_store import LearningStore

# Scanner tools
from tools.iot_scanner import scan_iot_device
from tools.keymgmt_scanner import scan_key_management
from tools.quantum_readiness_scanner import scan_quantum_readiness

logger = logging.getLogger("pqc.iot_edge_agent")

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"


class IoTEdgeAgent(BaseAgent):
    """
    Specialized agent for scanning IoT & Edge infrastructure.

    Evaluates 5 parameters per asset:
      1. Firmware Signing     (weight: 0.30)
      2. Device Longevity     (weight: 0.25)
      3. OTA Security         (weight: 0.20)
      4. Key Management       (weight: 0.15)
      5. Quantum Readiness    (weight: 0.10)

    Produces a 1–10 rating and priority-ranked migration list.
    """

    def __init__(self):
        super().__init__(agent_name="iot_edge_agent")
        self.scoring_engine = ScoringEngine(domain="iot_edge")
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
implementations and recommend NIST-approved PQC replacements.

For each asset you analyze, you will receive scan results from security parameters:
1. Firmware Signing — Algorithms used to sign firmware (e.g. RSA, LMS, XMSS)
2. Device Longevity — Expected lifespan relative to the quantum threat year (2030)
3. OTA Security — Secure update channels and their signing algorithms
4. Key Management — Storage, rotation, algorithms for device keys
5. Quantum Readiness — PQC deployment, hybrid mode, crypto agility

Your analysis should:
- Identify the most critical vulnerabilities, particularly for long-lived devices
- Explain WHY each finding is a quantum risk (reference Shor's algorithm, Harvest-Now-Decrypt-Later)
- Provide specific, actionable migration recommendations
- Reference NIST standards (NIST SP 800-208 for stateful hash-based signatures)
- Consider that field-deployed IoT devices often cannot be easily updated

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
            return None

    # ── Deterministic Tool Scanning ─────────────────────────────────────────

    def _scan_asset_tools(self, target: dict) -> dict:
        """
        Run scanner tools on a single IoT asset. Returns raw scores.
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
        else:
            scores["firmware_signing"] = (None, "No firmware metadata provided")
            scores["device_longevity"] = (None, "No longevity data provided")
            scores["ota_security"] = (None, "No OTA data provided")

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
        else:
            scores["key_management"] = (None, "No key management data provided")

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
        else:
            scores["quantum_readiness"] = (None, "No verifiable quantum readiness data provided")

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
            if score is None:
                continue

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
            asset_rating = self.scoring_engine.score_asset(
                asset=asset,
                scores=scan_result["scores"],
                findings=scan_result["findings"],
                recommendations=recommendations,
            )

            ratings.append(asset_rating)

            # Step 4: Record in learning store
            self.learning_store.record_scan(
                asset=asset,
                rating=asset_rating.rating,
                parameter_scores={
                    p.name: p.score for p in asset_rating.parameter_scores
                },
                findings_summary=f"{len(scan_result['findings'])} findings, "
                                 f"rating {asset_rating.rating}/10 ({asset_rating.verdict})",
                run_id=self.run_id,
            )

            # Also add to base agent findings
            for finding in scan_result["findings"]:
                self.findings.append(finding)

            logger.info(
                f"  [{i}/{len(targets)}] {asset}: "
                f"Rating {asset_rating.rating}/10 — {asset_rating.verdict}"
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

        print(f"\n📊 Learning Store: {agent.learning_store.summary()}")
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
            "hardware_root_of_trust": False
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
        }
    }


def run_interactive_cli():
    import time

    BANNER = """
  ╔═════════════════════════════════════════════════════════════════════╗
  ║    PQC IoT & EDGE AGENT  v1.0  -  Strands SDK + Amazon Bedrock      ║
  ║    Post-Quantum Cryptography Migration Scanner — IoT & Edge         ║
  ╠═════════════════════════════════════════════════════════════════════╣
  ║ Standards:  NIST SP 800-208  ·  FIPS 203/204/205  ·  CNSA 2.0       ║
  ║             Stateful Hash-Based Signatures (LMS / XMSS)             ║
  ╠═════════════════════════════════════════════════════════════════════╣
  ║ Commands:                                                           ║
  ║   scan        - Full scan + report for a device or mock dataset     ║
  ║   list        - List available mock datasets                        ║
  ║   help        - Show command reference                              ║
  ║   exit        - Quit the agent                                      ║
  ╚═════════════════════════════════════════════════════════════════════╝
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
                    print(f"\nScanning IoT device profile: {target_arg}...")
                    targets = {"scan_targets": [_generate_mock_iot_target(target_arg)]}
                    assessment = agent.scan(targets)
                    agent.save_local()

                if assessment:
                    print("\nRESULTS:")
                    for item in assessment.get("rated_assets", []):
                        print(f"\n{'─' * 60}")
                        print(f"  #{item['priority_rank']} │ {item['asset']}")
                        print(f"     Rating:  {item['rating']}/10 — {item['verdict']}")
                        print(f"     Action:  {item['action']}")
                        print(f"     Score:   {item['weighted_score']:.4f}")
                        print(f"     Params:")
                        for param, data in item.get("parameter_scores", {}).items():
                            if data["score"] is None:
                                bar = "░" * 20
                                print(f"       {param:25s} {bar} N/A (Not Assessed)")
                            else:
                                bar = "█" * int(data["score"] * 20) + "░" * (20 - int(data["score"] * 20))
                                print(f"       {param:25s} {bar} {data['score']:.2f}")

                    # Automatically export PDF report
                    try:
                        from core.pdf_report_generator import PdfReportGenerator
                        generator = PdfReportGenerator()
                        pdf_path = generator.generate_report(assessment, domain_name=f"IoT_{target_arg}")
                        print(f"\n📄 Complete Risk Assessment PDF exported to: {pdf_path}")
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

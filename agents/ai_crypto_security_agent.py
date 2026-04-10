"""
Algorithms & Network Protocols Agent — Enhanced with Regional Compliance

Enhanced implementation using Strands SDK + AWS Bedrock (Claude 3.5 Sonnet).
Scans cryptographic algorithms and network protocols for quantum-vulnerable
implementations across 10 parameters, produces 0–100 ratings per asset,
and ranks them by migration priority.

Enhancements:
  - 10 parameters (expanded from basic TLS/GitHub scan)
  - Regional compliance support (12 regions)
  - 100-point scoring scale
  - Subdomain discovery
  - Git repository scanning
  - Dynamic priority ranking

Architecture:
  1. Loads target data (mock, domain, git repo, or custom)
  2. Runs 10 scanner tools deterministically for raw scores
  3. Feeds findings to Strands AI agent for analysis + recommendations
  4. Scoring engine computes weighted rating (0–100) with regional weights
  5. Learning store records results for RL-style improvement
  6. Outputs priority-ranked assessment

Works independently of AWS — Bedrock is used only for the AI analysis
layer. Scoring, tools, and learning all run locally.
"""

from __future__ import annotations

import sys
import os

# Fix Windows console encoding for box-drawing characters
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import json
import logging
import os
import re
import ssl
import socket
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlparse

# Add project root to sys.path so direct execution works
_current_dir = Path(__file__).resolve().parent
_project_root = _current_dir.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from core.base_agent import BaseAgent
from core.learning_store import LearningStore
# Regional standards support
from core.enhanced_region_standards import get_enhanced_region_profile
from core.enhanced_scoring_engine import EnhancedScoringEngine

# Scanner tools (10 parameters total)
from tools.tls_scanner import scan_tls_config
from tools.network_scanner import scan_network_protocol
from tools.public_key_scanner import scan_public_key_config
from tools.symmetric_scanner import scan_symmetric_config
from tools.keymgmt_scanner import scan_key_management
from tools.quantum_readiness_scanner import scan_quantum_readiness
# Additional enhanced scanners
from tools.enhanced_scanners import (
    scan_certificate_security,
    scan_regulatory_compliance,
)
# Advanced features
from tools.subdomain_discovery import discover_subdomains_for_assessment

logger = logging.getLogger("pqc.ai_crypto_security_agent")

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"

# ── Crypto patterns for source code audit ────────────────────────────────────
CRYPTO_PATTERNS = {
    "AES":       r"\bAES\b",
    "RSA":       r"\bRSA\b",
    "MD5":       r"\bMD5\b",
    "SHA1":      r"\bSHA[-_]?1\b",
    "SHA256":    r"\bSHA[-_]?256\b",
    "KYBER":     r"\bKYBER\b",
    "DILITHIUM": r"\bDILITHIUM\b",
    "ML-KEM":    r"\bML[-_]KEM\b",
    "ML-DSA":    r"\bML[-_]DSA\b",
    "ECDSA":     r"\bECDSA\b",
    "DH":        r"\bDiffie[-_]?Hellman\b|\bDH[-_]\d",
    "3DES":      r"\b3DES\b|\bTriple[-_]?DES\b",
}
SUPPORTED_EXT = (".py", ".c", ".cpp", ".h", ".java", ".js", ".go", ".rs", ".ts", ".rb")


class AlgorithmsNetworkAgent(BaseAgent):
    """
    Enhanced agent for scanning Algorithms & Network Protocol infrastructure.

    Evaluates 10 parameters per asset:
      1.  TLS/Transport         (weight: 15%)
      2.  Public Key Crypto     (weight: 12%)
      3.  Symmetric Crypto      (weight: 10%)
      4.  Network Protocols     (weight: 12%)
      5.  Quantum Readiness     (weight: 8%)
      6.  Certificate Security  (weight: 10%)
      7.  Hash Algorithms       (weight: 8%)
      8.  Key Management        (weight: 8%)
      9.  Code Crypto Audit     (weight: 9%)
      10. Regulatory Compliance (weight: 8%)

    Produces a 0–100 rating with regional weighting and priority-ranked migration list.

    Enhanced Features:
    - Regional compliance support (12 regions)
    - Subdomain discovery
    - Git repository scanning for crypto patterns
    - 100-point scoring scale
    - Dynamic priority ranking
    """

    def __init__(self, region: str = "US"):
        super().__init__(agent_name="ai_crypto_security_agent")
        self.region = region.upper()
        self.region_profile = get_enhanced_region_profile(self.region)
        self.scoring_engine = EnhancedScoringEngine(domain="algorithms_network", region=self.region)
        self.learning_store = LearningStore(agent_name="ai_crypto_security_agent")
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

Your job is to analyze cryptographic algorithms and network protocol infrastructure for
quantum-vulnerable implementations and recommend region-specific PQC replacements.

Regional Context: {self.region} ({self.region_profile['name']})
Regulatory Body: {self.region_profile['body_full']}
Standards: {', '.join(self.region_profile['standards'])}
Compliance Deadline: {self.region_profile['deadline']}

For each asset you analyze, you will receive scan results from 10 security parameters:
1.  TLS/Transport — TLS version, key exchange, ciphers, HSTS
2.  Public Key Crypto — RSA/ECC/DH key exchange and digital signatures
3.  Symmetric Crypto — AES/3DES/ChaCha20 (Grover's algorithm impact)
4.  Network Protocols — SSH key exchange, IKEv2/IPsec, VPN configurations
5.  Quantum Readiness — PQC deployment, hybrid mode, crypto agility
6.  Certificate Security — Certificate algorithms, validity periods, chain depth
7.  Hash Algorithms — MD5/SHA-1/SHA-256 usage assessment
8.  Key Management — Key storage, rotation, algorithms
9.  Code Crypto Audit — Source code cryptographic pattern analysis
10. Regulatory Compliance — {self.region_profile['body']} requirements, documentation

Your analysis should:
- Identify the most critical algorithm vulnerabilities
- Explain WHY each finding is a quantum risk (reference Shor's/Grover's algorithm)
- Provide specific, actionable migration recommendations with NIST FIPS references
- Reference {self.region_profile['body']} standards and compliance deadlines
- Consider the "harvest now, decrypt later" (HNDL) threat model
- Provide 0-100 scoring context with regional priorities

{learning_ctx}
"""

            self._strands_agent = Agent(
                model=model,
                system_prompt=system_prompt,
                tools=[
                    scan_tls_config,
                    scan_network_protocol,
                    scan_public_key_config,
                    scan_symmetric_config,
                    scan_key_management,
                    scan_quantum_readiness,
                    scan_certificate_security,
                    scan_regulatory_compliance,
                ],
            )
            logger.info("Strands AI agent initialized with Bedrock")
            return self._strands_agent

        except Exception as e:
            logger.warning(f"Could not initialize Strands agent: {e}")
            logger.info("Running in local-only mode (deterministic scoring, no AI analysis)")
            self._strands_agent_failed = True
            return None

    # ── GitHub Repo Scanning ────────────────────────────────────────────────

    @staticmethod
    def _clone_repo(url: str) -> str:
        """Clone a Git repository to a temp directory."""
        temp = tempfile.mkdtemp()
        subprocess.run(
            ["git", "clone", "--depth", "1", url, temp],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return temp

    @staticmethod
    def _scan_repo_patterns(path: str) -> list[str]:
        """Scan repository source code for cryptographic algorithm patterns."""
        algos = set()
        for root, _, files in os.walk(path):
            for f in files:
                if f.endswith(SUPPORTED_EXT):
                    try:
                        content = open(os.path.join(root, f), errors="ignore").read()
                        for name, pattern in CRYPTO_PATTERNS.items():
                            if re.search(pattern, content, re.IGNORECASE):
                                algos.add(name)
                    except Exception:
                        pass
        return list(algos)

    # ── Deterministic Tool Scanning ─────────────────────────────────────────

    def _scan_asset_tools(self, target: dict) -> dict:
        """
        Run all 10 scanner tools on a single asset. Returns raw scores.
        This runs locally — no LLM needed.
        """
        scores = {}
        all_findings = []

        asset = target.get("asset", "unknown")

        # 1. TLS/Transport Security
        tls_config = target.get("tls_config", {})
        if tls_config and tls_config.get("tls_version", "unknown") != "unknown":
            tls_result = json.loads(scan_tls_config(config=json.dumps(tls_config)))
            scores["tls_transport"] = (
                tls_result.get("score", 0.0),
                f"TLS {tls_config.get('tls_version', '?')} + {tls_config.get('key_exchange', '?')}"
            )
            all_findings.extend([
                {"parameter": "tls_transport", "asset": asset, **f}
                for f in tls_result.get("findings", [])
            ])
        else:
            scores["tls_transport"] = (None, "No TLS config provided")

        # 2. Public Key Crypto
        pk_config = target.get("public_key_config", {})
        if pk_config and pk_config.get("algorithm"):
            pk_result = json.loads(scan_public_key_config(config=json.dumps(pk_config)))
            is_vulnerable = pk_result.get("quantum_vulnerable", False)
            risk = pk_result.get("risk_level", "INFO")
            # Map risk to score
            risk_scores = {"CRITICAL": 0.1, "HIGH": 0.3, "MEDIUM": 0.5, "LOW": 0.8, "INFO": 0.9}
            pk_score = risk_scores.get(risk, 0.5)
            scores["public_key_crypto"] = (
                pk_score,
                f"{pk_config.get('algorithm', '?')}-{pk_config.get('key_size', '?')} ({pk_config.get('usage', '?')})"
            )
            if is_vulnerable:
                all_findings.append({
                    "parameter": "public_key_crypto",
                    "asset": asset,
                    "risk_level": risk,
                    "reason": pk_result.get("reason", ""),
                    "algorithm": pk_config.get("algorithm", "unknown"),
                })
        else:
            scores["public_key_crypto"] = (None, "No public key config provided")

        # 3. Symmetric Crypto
        sym_config = target.get("symmetric_config", {})
        if sym_config and sym_config.get("algorithm"):
            sym_result = json.loads(scan_symmetric_config(config=json.dumps(sym_config)))
            is_vulnerable = sym_result.get("quantum_vulnerable", False)
            risk = sym_result.get("risk_level", "LOW")
            risk_scores = {"CRITICAL": 0.1, "HIGH": 0.3, "MEDIUM": 0.5, "LOW": 0.9, "INFO": 0.9}
            sym_score = risk_scores.get(risk, 0.5)
            scores["symmetric_crypto"] = (
                sym_score,
                f"{sym_config.get('algorithm', '?')}-{sym_config.get('mode', '?')} "
                f"(post-quantum: {sym_result.get('post_quantum_strength_bits', '?')} bits)"
            )
            if is_vulnerable:
                all_findings.append({
                    "parameter": "symmetric_crypto",
                    "asset": asset,
                    "risk_level": risk,
                    "reason": sym_result.get("reason", ""),
                    "algorithm": sym_config.get("algorithm", "unknown"),
                })
        else:
            scores["symmetric_crypto"] = (None, "No symmetric crypto config provided")

        # 4. Network Protocols (SSH, IKEv2, VPN)
        net_config = target.get("network_protocol_config", {})
        if net_config and net_config.get("protocol"):
            net_result = json.loads(scan_network_protocol(config=json.dumps(net_config)))
            num_findings = net_result.get("total_findings", 0)
            # Score based on number and severity of findings
            if num_findings == 0:
                net_score = 0.9
            else:
                # Check severity
                has_critical = any(
                    f.get("risk_level") == "CRITICAL"
                    for f in net_result.get("findings", [])
                )
                has_high = any(
                    f.get("risk_level") == "HIGH"
                    for f in net_result.get("findings", [])
                )
                if has_critical:
                    net_score = 0.15
                elif has_high:
                    net_score = 0.35
                else:
                    net_score = 0.6
            scores["network_protocols"] = (
                net_score,
                f"{net_config.get('protocol', '?')} {net_config.get('version', '?')} "
                f"({num_findings} findings)"
            )
            all_findings.extend([
                {"parameter": "network_protocols", "asset": asset, **f}
                for f in net_result.get("findings", [])
            ])
        else:
            scores["network_protocols"] = (None, "No network protocol config provided")

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
            scores["quantum_readiness"] = (None, "No verifiable quantum readiness data")

        # 6. Certificate Security
        cert_config = target.get("certificate_security", {})
        if cert_config and cert_config.get("cert_algorithm"):
            cert_result = json.loads(scan_certificate_security(config=json.dumps(cert_config)))
            scores["certificate_security"] = (
                cert_result.get("score", 0.0),
                f"Cert: {cert_config.get('cert_algorithm', '?')}, "
                f"{cert_config.get('validity_years', '?')}y validity"
            )
            all_findings.extend([
                {"parameter": "certificate_security", "asset": asset, **f}
                for f in cert_result.get("findings", [])
            ])
        else:
            scores["certificate_security"] = (None, "No certificate data provided")

        # 7. Hash Algorithms
        hash_config = target.get("hash_config", {})
        if hash_config and hash_config.get("algorithms_in_use"):
            algos_in_use = hash_config.get("algorithms_in_use", [])
            hash_score = 1.0
            hash_details = []

            for algo in algos_in_use:
                algo_upper = algo.upper()
                if "MD5" in algo_upper:
                    hash_score -= 0.4
                    hash_details.append("MD5 (broken)")
                    all_findings.append({
                        "parameter": "hash_algorithms",
                        "asset": asset,
                        "risk_level": "CRITICAL",
                        "reason": "MD5 is cryptographically broken — collision attacks trivial",
                        "algorithm": "MD5",
                    })
                elif "SHA1" in algo_upper or "SHA-1" in algo_upper:
                    hash_score -= 0.3
                    hash_details.append("SHA-1 (deprecated)")
                    all_findings.append({
                        "parameter": "hash_algorithms",
                        "asset": asset,
                        "risk_level": "HIGH",
                        "reason": "SHA-1 deprecated, practical collision attacks demonstrated",
                        "algorithm": "SHA-1",
                    })
                else:
                    hash_details.append(f"{algo} (OK)")

            # Check password hashing
            pw_hash = hash_config.get("password_hashing", "")
            if pw_hash.upper() in ("MD5", "SHA1", "SHA-1"):
                hash_score -= 0.2
                all_findings.append({
                    "parameter": "hash_algorithms",
                    "asset": asset,
                    "risk_level": "CRITICAL",
                    "reason": f"Password hashing uses {pw_hash} — insecure",
                    "algorithm": pw_hash,
                })

            scores["hash_algorithms"] = (
                max(0.0, hash_score),
                "; ".join(hash_details)
            )
        else:
            scores["hash_algorithms"] = (None, "No hash algorithm data provided")

        # 8. Key Management
        keymgmt_config = target.get("key_management", {})
        if keymgmt_config and keymgmt_config.get("storage_type", "unknown") != "unknown":
            km_result = json.loads(scan_key_management(config=json.dumps(keymgmt_config)))
            scores["key_management"] = (
                km_result.get("score", 0.0),
                f"{keymgmt_config.get('storage_type', '?')} storage, "
                f"{keymgmt_config.get('rotation_policy', '?')}"
            )
            all_findings.extend([
                {"parameter": "key_management", "asset": asset, **f}
                for f in km_result.get("findings", [])
            ])
        else:
            scores["key_management"] = (None, "No key management data provided")

        # 9. Code Crypto Audit
        code_config = target.get("code_audit", {})
        repo_url = code_config.get("repo_url", "")
        detected_algos = code_config.get("detected_algorithms", [])

        # If there's a repo URL, try to scan it
        if repo_url and "github.com" in repo_url:
            try:
                print(f"  [*] Cloning repository {repo_url}...")
                repo_path = self._clone_repo(repo_url)
                detected_algos = self._scan_repo_patterns(repo_path)
                code_config["detected_algorithms"] = detected_algos
            except Exception as e:
                logger.warning(f"Failed to clone repo: {e}")

        if detected_algos:
            code_score = 1.0
            code_details = []

            for algo in detected_algos:
                algo_upper = algo.upper()
                if algo_upper == "MD5":
                    code_score -= 0.35
                    code_details.append("MD5 (broken)")
                elif algo_upper in ("SHA1", "SHA-1"):
                    code_score -= 0.25
                    code_details.append("SHA-1 (weak)")
                elif algo_upper == "RSA":
                    code_score -= 0.1
                    code_details.append("RSA (quantum risk)")
                elif algo_upper in ("DH", "3DES"):
                    code_score -= 0.15
                    code_details.append(f"{algo} (quantum risk)")
                elif algo_upper in ("ECDSA", "ECC"):
                    code_score -= 0.1
                    code_details.append(f"{algo} (quantum risk)")
                elif algo_upper in ("KYBER", "ML-KEM", "DILITHIUM", "ML-DSA"):
                    code_score += 0.05
                    code_details.append(f"{algo} (PQC ✓)")
                else:
                    code_details.append(f"{algo} (OK)")

            scores["code_crypto_audit"] = (
                max(0.0, min(1.0, code_score)),
                "; ".join(code_details[:5]) + ("..." if len(code_details) > 5 else "")
            )
        elif code_config.get("crypto_libraries"):
            # No specific algorithm detection but have libraries
            scores["code_crypto_audit"] = (
                0.5,
                f"Libraries: {', '.join(code_config.get('crypto_libraries', []))}"
            )
        else:
            scores["code_crypto_audit"] = (None, "No code audit data available")

        # 10. Regulatory Compliance
        compliance_config = target.get("regulatory_compliance", {})
        if compliance_config and (compliance_config.get("frameworks") or compliance_config.get("pqc_migration_plan") is not None):
            compliance_result = json.loads(scan_regulatory_compliance(config=json.dumps(compliance_config)))
            scores["regulatory_compliance"] = (
                compliance_result.get("score", 0.0),
                f"Frameworks: {len(compliance_config.get('frameworks', []))}, "
                f"PQC plan: {compliance_config.get('pqc_migration_plan', False)}"
            )
            all_findings.extend([
                {"parameter": "regulatory_compliance", "asset": asset, **f}
                for f in compliance_result.get("findings", [])
            ])
        else:
            scores["regulatory_compliance"] = (None, "No regulatory compliance data provided")

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
            prompt = f"""Analyze the following PQC scan results for asset "{asset}":

Parameter Scores (0.0 = insecure, 1.0 = quantum-safe):
{json.dumps({k: {"score": v[0], "details": v[1]} for k, v in scores.items()}, indent=2)}

Findings:
{json.dumps(findings, indent=2)}

Provide:
1. A brief overall assessment (2-3 sentences)
2. Top 3 prioritized migration recommendations with specific NIST standards
3. Estimated migration complexity (Low/Medium/High) for each recommendation
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
                if param_name == "tls_transport":
                    recommendations.append(
                        "CRITICAL: Upgrade to TLS 1.3 with hybrid PQC key exchange "
                        "(X25519+ML-KEM-768). Current transport layer is quantum-vulnerable."
                    )
                elif param_name == "public_key_crypto":
                    recommendations.append(
                        "CRITICAL: Replace RSA/ECC public key algorithms with ML-KEM (FIPS 203) "
                        "for key exchange and ML-DSA (FIPS 204) for digital signatures. "
                        "Current algorithms are broken by Shor's algorithm."
                    )
                elif param_name == "symmetric_crypto":
                    recommendations.append(
                        "HIGH: Upgrade symmetric encryption to AES-256 minimum. "
                        "Grover's algorithm halves effective key strength (AES-128 → 64-bit)."
                    )
                elif param_name == "network_protocols":
                    recommendations.append(
                        "CRITICAL: Network protocols use quantum-vulnerable key exchange. "
                        "Migrate SSH to sntrup761+x25519 (OpenSSH 9.0+), "
                        "IKEv2 to ML-KEM hybrid key exchange."
                    )
                elif param_name == "quantum_readiness":
                    recommendations.append(
                        "HIGH: No PQC awareness detected. Implement crypto agility and "
                        "begin PQC testing with NIST FIPS 203/204/205 targets."
                    )
                elif param_name == "certificate_security":
                    recommendations.append(
                        "HIGH: Certificates use quantum-vulnerable algorithms. "
                        "Plan migration to ML-DSA (FIPS 204) signed certificates."
                    )
                elif param_name == "hash_algorithms":
                    recommendations.append(
                        "CRITICAL: Broken hash algorithms detected (MD5/SHA-1). "
                        "Migrate to SHA-256 or SHA-3 immediately."
                    )
                elif param_name == "key_management":
                    recommendations.append(
                        "CRITICAL: Move keys to HSM/KMS with auto-rotation. "
                        "Migrate key algorithms to ML-KEM/ML-DSA."
                    )
                elif param_name == "code_crypto_audit":
                    recommendations.append(
                        "HIGH: Source code uses deprecated/vulnerable cryptographic algorithms. "
                        "Refactor to use quantum-safe libraries and remove MD5/SHA-1 usage."
                    )
                elif param_name == "regulatory_compliance":
                    recommendations.append(
                        "MEDIUM: No PQC migration plan documented. "
                        "Develop a comprehensive roadmap aligned with NIST IR 8547 guidelines."
                    )
            elif score < 0.6:
                recommendations.append(
                    f"MEDIUM: Improve {param_name} ({details}). "
                    f"Score {score:.1f}/1.0 indicates partial quantum exposure."
                )

        if not recommendations:
            recommendations.append(
                "Asset has reasonable quantum posture. Continue monitoring for PQC standards updates."
            )

        return recommendations

    # ── Main Scan Method ────────────────────────────────────────────────────

    def scan(self, target: dict) -> dict:
        """
        Scan algorithm/protocol targets for quantum-vulnerable crypto.

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

        logger.info(f"Scanning {len(targets)} Algorithm/Protocol assets...")

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

            # Step 3: Compute weighted score → 0–100 rating
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
        logger.info(f"\n{'='*72}\nPQC Migration Priority Ranking — Algorithms & Network Protocols\n{'='*72}\n{summary}\n{'='*72}")

        return self.build_assessment()

    # ── Convenience: Load & Scan Mock Data ──────────────────────────────────

    @classmethod
    def scan_mock_data(cls, mock_file: str | None = None) -> dict:
        """
        Convenience method to load mock data and run a full scan.

        Args:
            mock_file: Path to mock JSON file. Defaults to data/mock_crypto_targets.json

        Returns:
            Full assessment with rated assets.
        """
        if mock_file is None:
            mock_file = str(_DATA_DIR / "mock_crypto_targets.json")

        with open(mock_file, "r") as f:
            targets = json.load(f)

        agent = cls()
        assessment = agent.scan(targets)
        agent.save_local()

        print(f"\n[*] Learning Store: {agent.learning_store.summary()}")
        return assessment


# ── Helper: Passive Domain Reconnaissance ─────────────────────────────────

def _fetch_public_domain_data(domain: str) -> dict:
    """Passively collect TLS/certificate data from a public domain."""
    import urllib.request

    print(f"  [+] Passively analyzing public footprint of {domain} ...")

    target = {
        "asset": domain,
        "description": f"Passively detected structure for {domain}",
        "tls_config": {
            "tls_version": "unknown",
            "key_exchange": "unknown",
            "cert_key_type": "unknown",
            "cipher_suite": "unknown",
            "hsts_enabled": False,
            "cert_pinning": False
        },
        "public_key_config": {
            "algorithm": "RSA",
            "key_size": 2048,
            "usage": "both",
            "context": f"TLS certificate for {domain}"
        },
        "symmetric_config": {
            "algorithm": "AES-128",
            "mode": "GCM",
            "context": "TLS data channel"
        },
        "network_protocol_config": {
            "protocol": "TLS",
            "version": "1.2",
            "key_exchange": "unknown",
            "context": f"Web endpoint {domain}"
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
        "certificate_security": {
            "cert_algorithm": "RSA-2048",
            "validity_years": 1,
            "chain_depth": 3,
            "ca_trusted": True
        },
        "hash_config": {
            "algorithms_in_use": ["SHA256"],
            "password_hashing": "unknown",
            "integrity_check": "SHA256"
        },
        "key_management": {
            "storage_type": "unknown",
            "rotation_policy": "unknown",
            "key_algorithm": "unknown",
            "key_count": 0,
            "separation_of_duties": False,
            "audit_logging": False,
            "backup_exists": False
        },
        "code_audit": {
            "repo_url": "",
            "languages": [],
            "crypto_libraries": [],
            "detected_algorithms": []
        },
        "regulatory_compliance": {
            "frameworks": [],
            "pqc_migration_plan": False,
            "audit_logging": False,
            "crypto_documentation": False
        }
    }

    # Extract TLS & Certificate details via passive probing
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((domain, 443), timeout=5.0) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cipher = ssock.cipher()
                tls_version_raw = cipher[1] if cipher else "unknown"

                # Map TLSv1.3 → 1.3 for scanner compatibility
                tls_version_map = {
                    "TLSv1.3": "1.3", "TLSv1.2": "1.2",
                    "TLSv1.1": "1.1", "TLSv1": "1.0",
                }
                tls_version = tls_version_map.get(tls_version_raw, tls_version_raw)

                cipher_suite_raw = cipher[0] if cipher else "unknown"

                # Determine cipher suite for scoring
                if "GCM" in cipher_suite_raw and "256" in cipher_suite_raw:
                    cipher_mapped = "AES_256_GCM"
                elif "GCM" in cipher_suite_raw:
                    cipher_mapped = "AES_128_GCM"
                elif "CHACHA20" in cipher_suite_raw:
                    cipher_mapped = "CHACHA20_POLY1305"
                else:
                    cipher_mapped = cipher_suite_raw

                # Determine key exchange
                if "ECDHE" in cipher_suite_raw:
                    ke_mapped = "ECDHE_P256"
                elif tls_version == "1.3":
                    ke_mapped = "X25519"
                else:
                    ke_mapped = "RSA"

                target["tls_config"] = {
                    "tls_version": tls_version,
                    "key_exchange": ke_mapped,
                    "cert_key_type": "RSA_2048",
                    "cipher_suite": cipher_mapped,
                    "hsts_enabled": False,
                    "cert_pinning": False
                }
                target["network_protocol_config"] = {
                    "protocol": "TLS",
                    "version": tls_version,
                    "key_exchange": ke_mapped,
                    "cipher_suites": [cipher_suite_raw],
                    "context": f"Web endpoint {domain}"
                }
                # Update symmetric based on detected cipher
                if "256" in cipher_suite_raw:
                    target["symmetric_config"]["algorithm"] = "AES-256"
                elif "CHACHA" in cipher_suite_raw:
                    target["symmetric_config"]["algorithm"] = "ChaCha20"
                else:
                    target["symmetric_config"]["algorithm"] = "AES-128"

    except Exception as e:
        print(f"      - TLS connection failed: {e}")

    return target


def _domain_to_crypto_target(subdomain_target: dict) -> dict:
    """Convert a subdomain discovery target into a crypto assessment target."""
    domain = subdomain_target.get("asset", "unknown")
    tls = subdomain_target.get("tls_config", {})
    tls_version = tls.get("tls_version", "1.2")

    return {
        "asset": domain,
        "description": f"Discovered endpoint: {domain}",
        "tls_config": tls,
        "public_key_config": {
            "algorithm": "RSA",
            "key_size": 2048,
            "usage": "both",
            "context": f"TLS certificate for {domain}"
        },
        "symmetric_config": {
            "algorithm": "AES-256" if "1.3" in str(tls_version) else "AES-128",
            "mode": "GCM",
            "context": "TLS data channel"
        },
        "network_protocol_config": {
            "protocol": "TLS",
            "version": str(tls_version).replace("TLSv", ""),
            "key_exchange": tls.get("key_exchange", "unknown"),
            "context": f"Web endpoint {domain}"
        },
        "quantum_readiness": subdomain_target.get("quantum_readiness", {
            "pqc_algorithms_deployed": [], "hybrid_mode_enabled": False,
            "crypto_agile": False, "migration_plan_exists": False,
            "migration_plan_timeline": "", "pqc_testing_done": False,
            "library_supports_pqc": False
        }),
        "certificate_security": subdomain_target.get("certificate_security", {
            "cert_algorithm": "RSA-2048", "validity_years": 1,
            "chain_depth": 3, "ca_trusted": True
        }),
        "hash_config": {
            "algorithms_in_use": ["SHA256"],
            "password_hashing": "unknown",
            "integrity_check": "SHA256"
        },
        "key_management": subdomain_target.get("key_management", {
            "storage_type": "unknown", "rotation_policy": "unknown",
            "key_algorithm": "unknown", "key_count": 0,
            "separation_of_duties": False, "audit_logging": False,
            "backup_exists": False
        }),
        "code_audit": {
            "repo_url": "", "languages": [],
            "crypto_libraries": [], "detected_algorithms": []
        },
        "regulatory_compliance": subdomain_target.get("regulatory_compliance", {
            "frameworks": [], "pqc_migration_plan": False,
            "audit_logging": False, "crypto_documentation": False
        }),
    }


# ── Interactive CLI Mode ──────────────────────────────────────────────────

def _generate_mock_crypto_target(name: str) -> dict:
    """Generate a plausible mock crypto target for interactive use."""
    return {
        "asset": name,
        "description": f"Algorithm/Protocol target: {name}",
        "tls_config": {
            "tls_version": "1.2",
            "key_exchange": "ECDHE_P256",
            "cert_key_type": "RSA_2048",
            "cipher_suite": "AES_128_GCM",
            "hsts_enabled": False,
            "cert_pinning": False
        },
        "public_key_config": {
            "algorithm": "RSA",
            "key_size": 2048,
            "usage": "both",
            "context": f"Default profile for {name}"
        },
        "symmetric_config": {
            "algorithm": "AES-128",
            "mode": "GCM",
            "context": "Data encryption"
        },
        "network_protocol_config": {
            "protocol": "TLS",
            "version": "1.2",
            "key_exchange": "ECDHE_P256",
            "cipher_suites": ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"],
            "context": f"Network endpoint {name}"
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
        "certificate_security": {
            "cert_algorithm": "RSA-2048",
            "validity_years": 2,
            "chain_depth": 3,
            "ca_trusted": True
        },
        "hash_config": {
            "algorithms_in_use": ["SHA256", "MD5"],
            "password_hashing": "bcrypt",
            "integrity_check": "SHA256"
        },
        "key_management": {
            "storage_type": "filesystem",
            "rotation_policy": "no_rotation",
            "key_algorithm": "RSA-2048",
            "key_count": 3,
            "separation_of_duties": False,
            "audit_logging": False,
            "backup_exists": True
        },
        "code_audit": {
            "repo_url": "",
            "languages": [],
            "crypto_libraries": ["openssl"],
            "detected_algorithms": ["RSA", "AES", "SHA256", "MD5"]
        },
        "regulatory_compliance": {
            "frameworks": [],
            "pqc_migration_plan": False,
            "audit_logging": False,
            "crypto_documentation": False
        }
    }


def run_interactive_cli():
    import time

    BANNER = """
  ╔═════════════════════════════════════════════════════════════════════╗
  ║  PQC ALGORITHMS & NETWORK PROTOCOLS AGENT  v1.0                    ║
  ║  Strands SDK + Amazon Bedrock                                      ║
  ║  Post-Quantum Cryptography Migration Scanner                       ║
  ╠═════════════════════════════════════════════════════════════════════╣
  ║ Standards:  NIST FIPS 203/204/205  ·  NIST IR 8547  ·  CNSA 2.0   ║
  ║             IETF PQ TLS  ·  OpenSSH 9.x  ·  PQ-VPN Drafts         ║
  ╠═════════════════════════════════════════════════════════════════════╣
  ║ 10-Parameter Analysis:                                             ║
  ║   TLS/Transport  ·  Public Key  ·  Symmetric  ·  Net Protocols     ║
  ║   Quantum Ready  ·  Certificates  ·  Hashing  ·  Key Mgmt         ║
  ║   Code Audit  ·  Regulatory Compliance                             ║
  ╠═════════════════════════════════════════════════════════════════════╣
  ║ Commands:                                                          ║
  ║   scan <domain>  - Passive domain scan + subdomain discovery       ║
  ║   scan mock      - Full scan on predefined mock dataset            ║
  ║   scan <name>    - Scan with default insecure profile              ║
  ║   report         - Show priority ranking of all scanned assets     ║
  ║   list           - List available mock datasets                    ║
  ║   help           - Show command reference                          ║
  ║   exit           - Quit the agent                                  ║
  ╚═════════════════════════════════════════════════════════════════════╝
"""
    MOCK_DATASETS = ['AcmeCorp-Crypto']

    print(BANNER)
    print("[*] Initialising Strands agent with Amazon Bedrock...\n")
    time.sleep(1)

    print("[*] PQC Algorithms & Network Protocols Agent -- Interactive Mode")
    print(f"Available mock datasets: {MOCK_DATASETS}")
    print("Type 'help' for suggested queries, 'exit' to quit.\n")

    all_assessments = []

    while True:
        try:
            cmd_line = input("You: ").strip()
            if not cmd_line:
                continue

            parts = cmd_line.split()
            cmd = parts[0].lower()
            args = parts[1:]

            if cmd in ("exit", "quit"):
                print("Exiting PQC Algorithms & Network Protocols Agent...")
                break
            elif cmd == "help":
                print("Commands:")
                print("  scan mock              - Full scan on predefined AcmeCorp Crypto mock dataset")
                print("  scan <domain.com>      - Passive domain scan with subdomain discovery")
                print("  scan <name>            - Scan a custom target with default insecure profile")
                print("  report                 - Show priority ranking of all scanned assets")
                print("  list                   - List available mock datasets")
            elif cmd == "list":
                print(f"Available mock datasets: {MOCK_DATASETS}")
            elif cmd == "report":
                if not all_assessments:
                    print("No scans completed yet. Run 'scan <target>' first.")
                else:
                    # Merge all rated assets and re-rank
                    all_rated = []
                    for a in all_assessments:
                        all_rated.extend(a.get("rated_assets", []))
                    all_rated.sort(key=lambda x: x.get("score_100", 0))
                    print(f"\n{'='*72}")
                    print("  COMBINED PRIORITY RANKING — All Scanned Assets")
                    print(f"{'='*72}")
                    for rank, item in enumerate(all_rated, 1):
                        print(f"  #{rank:2d} │ {item['asset']:30s} │ {item['score_100']:3d}/100 │ {item['verdict']}")
                    print(f"{'='*72}")

            elif cmd == "scan":
                agent = AlgorithmsNetworkAgent()
                target_arg = args[0] if args else "mock"
                assessment = None

                if target_arg == "mock" or target_arg in MOCK_DATASETS:
                    print("\nRunning scan on AcmeCorp Crypto mock data (3 assets)...")
                    assessment = AlgorithmsNetworkAgent.scan_mock_data()

                elif "github.com" in target_arg:
                    print(f"\nScanning GitHub repository: {target_arg}...")
                    repo_target = _generate_mock_crypto_target(target_arg)
                    repo_target["code_audit"]["repo_url"] = target_arg
                    targets = {"scan_targets": [repo_target]}
                    assessment = agent.scan(targets)
                    agent.save_local()

                else:
                    # Check if it looks like a domain
                    is_domain = bool(re.match(
                        r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$',
                        target_arg
                    ))

                    if is_domain:
                        print(f"\nDiscovering subdomains for: {target_arg}...")
                        subdomain_targets = discover_subdomains_for_assessment(target_arg)
                        if subdomain_targets:
                            crypto_targets = [_domain_to_crypto_target(t) for t in subdomain_targets]
                        else:
                            crypto_targets = [_fetch_public_domain_data(target_arg)]
                        targets = {"scan_targets": crypto_targets}
                    else:
                        print(f"\nScanning target profile: {target_arg}...")
                        targets = {"scan_targets": [_generate_mock_crypto_target(target_arg)]}

                    assessment = agent.scan(targets)
                    agent.save_local()

                if assessment:
                    all_assessments.append(assessment)
                    print("\nRESULTS:")
                    for item in assessment.get("rated_assets", []):
                        print(f"\n{'─' * 65}")
                        print(f"  #{item['priority_rank']} │ {item['asset']}")
                        print(f"     Rating:    {item['score_100']}/100 — {item['verdict']}")
                        print(f"     Priority:  {item['priority_level']}")
                        print(f"     Action:    {item['action']}")
                        print(f"     Score:     {item['weighted_score']:.4f}")
                        print(f"     Region:    {item.get('region', 'US')}")
                        print(f"     Params:")
                        for param, data in item.get("parameter_scores", {}).items():
                            if data["score"] is None:
                                bar = "░" * 20
                                print(f"       {param:25s} {bar} N/A (Not Assessed)")
                            else:
                                filled = int(data["score"] * 20)
                                bar = "█" * filled + "░" * (20 - filled)
                                print(f"       {param:25s} {bar} {data['score']:.2f} (weight: {data.get('effective_weight', 0):.2f})")

                        # Show recommendations
                        recs = item.get("migration_recommendations", [])
                        if recs:
                            print(f"\n     [>] Recommendations:")
                            for rec in recs[:3]:
                                # Truncate long recommendations for display
                                display = rec[:120] + "..." if len(rec) > 120 else rec
                                print(f"       → {display}")

                    # Automatically export PDF formal Report
                    try:
                        from core.pdf_report_generator import PdfReportGenerator
                        generator = PdfReportGenerator()
                        pdf_path = generator.generate_report(assessment, domain_name=f"Crypto_{target_arg}")
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

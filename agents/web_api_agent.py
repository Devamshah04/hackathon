"""
Web & API Services Agent - Enhanced with Regional Compliance

Enhanced implementation using Strands SDK + AWS Bedrock (Claude 3.5 Sonnet).
Scans web APIs for quantum-vulnerable cryptography across 10 parameters,
produces 0–100 ratings per asset, and ranks them by migration priority.

Enhancements:
  - 10 parameters (expanded from 5)
  - Regional compliance support (12 regions)
  - 100-point scoring scale
  - Subdomain discovery
  - Git repository scanning
  - Dynamic priority ranking

Architecture:
  1. Loads target data (mock, domain, or git repo)
  2. Runs 10 scanner tools deterministically for raw scores
  3. Feeds findings to Strands AI agent for analysis + recommendations
  4. Scoring engine computes weighted rating (0–100) with regional weights
  5. Learning store records results for RL-style improvement
  6. Outputs priority-ranked assessment

Works independently of AWS — Bedrock is used only for the AI analysis
layer. Scoring, tools, and learning all run locally.
"""

from __future__ import annotations

import sys as _sys
import os as _os

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
# Regional standards support
from core.enhanced_region_standards import get_enhanced_region_profile
from core.enhanced_scoring_engine import EnhancedScoringEngine

# Enhanced scanner tools (10 parameters total)
from tools.jwt_scanner import scan_jwt, ALGORITHM_SCORES
from tools.tls_scanner import scan_tls_config
from tools.oauth_scanner import scan_oauth_endpoint
from tools.keymgmt_scanner import scan_key_management
from tools.quantum_readiness_scanner import scan_quantum_readiness
# Additional enhanced scanners
from tools.enhanced_scanners import (
    scan_certificate_security,
    scan_api_encryption,
    scan_session_management,
    scan_data_at_rest,
    scan_regulatory_compliance
)
# Advanced features
from tools.subdomain_discovery import discover_subdomains_for_assessment

logger = logging.getLogger("pqc.web_api_agent")

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"


class WebApiAgent(BaseAgent):
    """
    Enhanced agent for scanning Web & API infrastructure with regional compliance.

    Evaluates 10 parameters per asset:
      1. Auth Token Crypto      (weight: 15%)
      2. TLS/Transport          (weight: 12%)
      3. OAuth/OIDC             (weight: 10%)
      4. Key Management         (weight: 12%)
      5. Quantum Readiness      (weight: 8%)
      6. Certificate Security   (weight: 10%)
      7. API Encryption         (weight: 8%)
      8. Session Management     (weight: 8%)
      9. Data at Rest           (weight: 9%)
      10. Regulatory Compliance (weight: 8%)

    Produces a 0–100 rating with regional weighting and priority-ranked migration list.
    
    Enhanced Features:
    - Regional compliance support (12 regions)
    - Subdomain discovery
    - Git repository scanning
    - 100-point scoring scale
    - Dynamic priority ranking
    """

    def __init__(self, region: str = "US"):
        super().__init__(agent_name="web_api_agent")
        self.region = region.upper()
        self.region_profile = get_enhanced_region_profile(self.region)
        self.scoring_engine = EnhancedScoringEngine(domain="web_api", region=self.region)
        self.learning_store = LearningStore(agent_name="web_api_agent")
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

Your job is to analyze Web & API infrastructure for quantum-vulnerable cryptographic
implementations and recommend region-specific PQC replacements.

Regional Context: {self.region} ({self.region_profile['name']})
Regulatory Body: {self.region_profile['body_full']}
Standards: {', '.join(self.region_profile['standards'])}
Compliance Deadline: {self.region_profile['deadline']}

For each asset you analyze, you will receive scan results from 10 security parameters:
1. Auth Token Crypto — JWT signing algorithms
2. TLS/Transport — TLS version, key exchange, certs, ciphers
3. OAuth/OIDC — token signing, PKCE, grant types, JWKS keys
4. Key Management — storage, rotation, algorithms
5. Quantum Readiness — PQC deployment, hybrid mode, crypto agility
6. Certificate Security — certificate algorithms, validity periods
7. API Encryption — payload encryption, field-level encryption
8. Session Management — session tokens, timeouts, security
9. Data at Rest — storage encryption, key protection
10. Regulatory Compliance — {self.region_profile['body']} requirements, documentation

Your analysis should:
- Identify the most critical vulnerabilities
- Explain WHY each finding is a quantum risk (reference Shor's/Grover's algorithm)
- Provide specific, actionable migration recommendations
- Reference {self.region_profile['body']} standards and compliance deadlines
- Consider the "harvest now, decrypt later" (HNDL) threat model
- Provide 0-100 scoring context with regional priorities

{learning_ctx}
"""

            self._strands_agent = Agent(
                model=model,
                system_prompt=system_prompt,
                tools=[
                    scan_jwt,
                    scan_tls_config,
                    scan_oauth_endpoint,
                    scan_key_management,
                    scan_quantum_readiness,
                    scan_certificate_security,
                    scan_api_encryption,
                    scan_session_management,
                    scan_data_at_rest,
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

    # ── Deterministic Tool Scanning ─────────────────────────────────────────

    def _scan_asset_tools(self, target: dict) -> dict:
        """
        Run all 5 scanner tools on a single asset. Returns raw scores.
        This runs locally — no LLM needed.
        """
        scores = {}
        all_findings = []

        asset = target.get("asset", "unknown")

        # 1. Auth Token Crypto (JWT analysis)
        jwt_token = target.get("jwt_token", "")
        if jwt_token:
            jwt_result = json.loads(scan_jwt(token=jwt_token))
            scores["auth_token_crypto"] = (
                jwt_result.get("score", 0.0),
                f"{jwt_result.get('algorithm', 'unknown')} signing — {jwt_result.get('reason', '')}"
            )
            if jwt_result.get("quantum_vulnerable"):
                all_findings.append({
                    "parameter": "auth_token_crypto",
                    "asset": asset,
                    **{k: v for k, v in jwt_result.items() if k != "token_header"},
                })
        else:
            logger.debug(f"  Skipping auth_token_crypto — no JWT data for {asset}")

        # 2. TLS/Transport Security
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

        # 3. OAuth/OIDC Security
        oauth_config = target.get("oauth_config", {})
        if oauth_config and oauth_config.get("endpoint_url"):
            oauth_result = json.loads(scan_oauth_endpoint(config=json.dumps(oauth_config)))
            scores["oauth_oidc"] = (
                oauth_result.get("score", 0.0),
                f"OAuth at {oauth_config.get('endpoint_url', '?')}"
            )
            all_findings.extend([
                {"parameter": "oauth_oidc", "asset": asset, **f}
                for f in oauth_result.get("findings", [])
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
        # If it's effectively default/empty structure
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

        # 6. Certificate Security
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

        # 7. API Encryption
        api_enc_config = target.get("api_encryption", {})
        if api_enc_config and api_enc_config.get("payload_encryption"):
            api_result = json.loads(scan_api_encryption(config=json.dumps(api_enc_config)))
            scores["api_encryption"] = (
                api_result.get("score", 0.0),
                f"Payload: {api_enc_config.get('payload_encryption', '?')}"
            )
            all_findings.extend([
                {"parameter": "api_encryption", "asset": asset, **f}
                for f in api_result.get("findings", [])
            ])

        # 8. Session Management
        session_config = target.get("session_management", {})
        if session_config and session_config.get("token_algorithm"):
            session_result = json.loads(scan_session_management(config=json.dumps(session_config)))
            scores["session_management"] = (
                session_result.get("score", 0.0),
                f"Token: {session_config.get('token_algorithm', '?')}, timeout: {session_config.get('timeout_minutes', '?')}m"
            )
            all_findings.extend([
                {"parameter": "session_management", "asset": asset, **f}
                for f in session_result.get("findings", [])
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
        if compliance_config and (compliance_config.get("frameworks") or compliance_config.get("pqc_migration_plan") is not None):
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
            logger.info(f"Using local deterministic recommendations for {asset} (AI AI bypassed: {e})")
            return self._generate_deterministic_recommendations(scores, findings)

    def _generate_deterministic_recommendations(self, scores: dict, findings: list) -> list[str]:
        """Generate rule-based recommendations when AI is unavailable."""
        recommendations = []

        for param_name, (score, details) in scores.items():

            if score < 0.3:
                if param_name == "auth_token_crypto":
                    recommendations.append(
                        "CRITICAL: Migrate JWT signing from RSA/ECDSA to ML-DSA (FIPS 204). "
                        "Current tokens are vulnerable to Shor's algorithm."
                    )
                elif param_name == "tls_transport":
                    recommendations.append(
                        "CRITICAL: Upgrade to TLS 1.3 with hybrid PQC key exchange "
                        "(X25519+ML-KEM-768). Current transport layer is quantum-vulnerable."
                    )
                elif param_name == "oauth_oidc":
                    recommendations.append(
                        "HIGH: Migrate OAuth token signing to ML-DSA, enable PKCE, "
                        "and audit JWKS keys for PQC readiness."
                    )
                elif param_name == "key_management":
                    recommendations.append(
                        "CRITICAL: Move keys to HSM/KMS with auto-rotation. "
                        "Migrate key algorithms to ML-KEM/ML-DSA."
                    )
                elif param_name == "quantum_readiness":
                    recommendations.append(
                        "HIGH: Implement crypto agility and begin PQC testing. "
                        "Create a migration plan with NIST FIPS 203/204 targets."
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
        Scan Web/API targets for quantum-vulnerable crypto.

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

        logger.info(f"Scanning {len(targets)} Web/API assets...")

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
        logger.info(f"\n{'='*72}\nPQC Migration Priority Ranking — Web & API\n{'='*72}\n{summary}\n{'='*72}")

        return self.build_assessment()

    # ── Convenience: Load & Scan Mock Data ──────────────────────────────────

    @classmethod
    def scan_mock_data(cls, mock_file: str | None = None) -> dict:
        """
        Convenience method to load mock data and run a full scan.

        Args:
            mock_file: Path to mock JSON file. Defaults to data/mock_web_api_targets.json

        Returns:
            Full assessment with rated assets.
        """
        if mock_file is None:
            mock_file = str(_DATA_DIR / "mock_web_api_targets.json")

        with open(mock_file, "r") as f:
            targets = json.load(f)

        agent = cls()
        assessment = agent.scan(targets)
        agent.save_local()

        print(f"\n[*] Learning Store: {agent.learning_store.summary()}")
        return assessment


# ── Interactive CLI Mode ──────────────────────────────────────────────────

def _fetch_public_domain_data(domain: str) -> dict:
    import ssl
    import socket
    import urllib.request
    import json
    
    print(f"  [+] Passively analyzing public footprint of {domain} ...")
    
    # 1. Base default structure
    target = {
        "asset": domain,
        "description": f"Passively detected structure for {domain}",
        "jwt_token": "", # Cannot fetch passively without auth
        "tls_config": {
            "tls_version": "unknown",
            "key_exchange": "unknown",
            "cert_key_type": "unknown",
            "cipher_suite": "unknown",
            "hsts_enabled": False,
            "cert_pinning": False
        },
        "oauth_config": {},
        "key_management": { # Internal structure cannot be fetched passively; mock a standard insecure baseline
            "storage_type": "unknown",
            "rotation_policy": "unknown",
            "key_algorithm": "unknown",
            "key_count": 0,
            "separation_of_duties": False,
            "audit_logging": False,
            "backup_exists": False
        },
        "quantum_readiness": { # Cannot be detected passively from outside
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
        "api_encryption": {
            "payload_encryption": "none",
            "field_level_encryption": False,
            "key_derivation": "PBKDF2"
        },
        "session_management": {
            "token_algorithm": "HMAC-SHA256",
            "timeout_minutes": 30,
            "secure_cookies": False,
            "regenerate_on_auth": False
        },
        "data_at_rest": {
            "encryption_algorithm": "AES-128",
            "key_storage": "filesystem",
            "key_rotation_days": 0
        },
        "regulatory_compliance": {
            "frameworks": [],
            "pqc_migration_plan": False,
            "audit_logging": False,
            "crypto_documentation": False
        }
    }

    # 2. Extract TLS & Certificate Details
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    try:
        with socket.create_connection((domain, 443), timeout=3.0) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                
                target["tls_config"] = {
                    "tls_version": cipher[1], # e.g. TLSv1.3 or TLSv1.2
                    "key_exchange": cipher[0].split("-")[0] if cipher[1] == "TLSv1.2" else "ECDHE/DHE", 
                    "cert_key_type": "RSA/ECDSA", # Need cryptography library for strict extraction, simplified here
                    "cipher_suite": cipher[0],
                    "hsts_enabled": False, # Requires HTTP fetch
                    "cert_pinning": False
                }
    except Exception as e:
        print(f"      - TLS connection failed: {e}")

    # 3. Check for OAuth config (OIDC discovery)
    url = f"https://{domain}/.well-known/openid-configuration"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=3.0) as response:
            if response.status == 200:
                data = json.loads(response.read().decode('utf-8'))
                target["oauth_config"] = {
                    "endpoint_url": url,
                    "signing_algorithms": data.get("id_token_signing_alg_values_supported", ["unknown"]),
                    "grant_types_supported": data.get("grant_types_supported", []),
                    "pkce_supported": "code_challenge_methods_supported" in data,
                    "jwks_key_types": ["unknown"],
                    "token_endpoint_auth_methods": data.get("token_endpoint_auth_methods_supported", [])
                }
    except Exception as e:
        pass # Expected to fail if endpoint doesn't exist

    return target

def run_interactive_cli():
    import time
    import sys
    
    # Mock dependencies for Strands if we are just running this locally without real AWS config setup
    if "strands" not in sys.modules:
        import types
        strands_mock = types.ModuleType("strands")
        class MockToolWrapper:
            def __init__(self, func):
                self.tool_function = func
                self.__name__ = func.__name__
                self.__doc__ = func.__doc__
            def __call__(self, *args, **kwargs):
                return self.tool_function(*args, **kwargs)
        strands_mock.tool = lambda f: MockToolWrapper(f)
        class MockAgent:
            def __init__(self, **kwargs):
                self.system_prompt = kwargs.get("system_prompt", "")
            def __call__(self, prompt):
                return None
        strands_mock.Agent = MockAgent
        models_mod = types.ModuleType("strands.models")
        bedrock_mod = types.ModuleType("strands.models.bedrock")
        bedrock_mod.BedrockModel = type("BedrockModel", (), {"__init__": lambda s, **k: None})
        sys.modules["strands"] = strands_mock
        sys.modules["strands.models"] = models_mod
        sys.modules["strands.models.bedrock"] = bedrock_mod

    BANNER = """
  ╔═════════════════════════════════════════════════════════════════════╗
  ║    PQC READINESS AGENT  v1.0   -   Strands SDK + Amazon Bedrock     ║
  ║    Post-Quantum Cryptography Migration Scanner                      ║
  ╠═════════════════════════════════════════════════════════════════════╣
  ║ Standards:  NIST FIPS 203/204/205  ·  NIST IR 8547  ·  CNSA 2.0     ║
  ║             NCSC UK  ·  BSI Germany  ·  ETSI  ·  ENISA  ·  ASD      ║
  ╠═════════════════════════════════════════════════════════════════════╣
  ║ Commands:                                                           ║
  ║   scan        - Full scan + report for a company or domain          ║
  ║   compare     - Side-by-side comparison of all companies            ║
  ║   interactive - Chat mode for custom queries                        ║
  ║   list        - List available companies and regions                ║
  ╚═════════════════════════════════════════════════════════════════════╝
"""
    MOCK_COMPANIES = ['AcmeCorp', 'MockCorp']

    print(BANNER)
    print("[*] Initialising Strands agent with Amazon Bedrock...\n")
    time.sleep(1) # simulate loading
    
    print("[*] PQC Readiness Agent - Interactive Mode")
    print(f"Available mock datasets: {MOCK_COMPANIES}")
    print("Type 'help' for suggested queries, 'exit' to quit.\n")
    
    while True:
        try:
            cmd_line = input("You: ").strip()
            if not cmd_line:
                continue
                
            parts = cmd_line.split()
            cmd = parts[0].lower()
            args = parts[1:]
            
            if cmd == "exit" or cmd == "quit":
                print("Exiting PQC Readiness Agent...")
                break
            elif cmd == "help":
                print("Commands:")
                print("  scan [domain/company] - Full scan + report (e.g. 'scan MockCorp' or 'scan example.com')")
                print("  scan mock             - Full scan on predefined mock dataset")
                print("  compare               - Feature coming soon!")
                print("  interactive           - Chat mode enabled")
                print("  list                  - List available mock datasets")
            elif cmd == "list":
                print(f"Available mock datasets: {MOCK_COMPANIES}")
            elif cmd == "scan":
                agent = WebApiAgent()
                target_arg = args[0] if args else "mock"
                
                if target_arg in MOCK_COMPANIES:
                    print(f"\nScanning mock company profile: {target_arg}...")
                    domain = f"api.{target_arg.lower()}.com"
                    targets = {"scan_targets": [_fetch_public_domain_data(domain)]}
                elif target_arg == "mock":
                    print("\nRunning scan on default mock data (all examples)...")
                    assessment = WebApiAgent.scan_mock_data()
                    targets = None
                else:
                    print(f"\nScanning public structure for domain: {target_arg}...")
                    domain = target_arg
                    subdomain_targets = discover_subdomains_for_assessment(domain)
                    if not subdomain_targets:
                        subdomain_targets = [_fetch_public_domain_data(domain)]
                    targets = {"scan_targets": subdomain_targets}

                if targets:
                    assessment = agent.scan(targets)
                    agent.save_local()
                
                print("\nRESULTS:")
                for item in assessment.get("rated_assets", []):
                    print(f"\n{'─' * 60}")
                    print(f"  #{item['priority_rank']} │ {item['asset']}")
                    print(f"     Rating:  {item['score_100']}/100 — {item['verdict']}")
                    print(f"     Action:  {item['action']}")
                    print(f"     Score:   {item['weighted_score']:.4f}")
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

                # Automatically export PDF formal Report
                try:
                    from core.pdf_report_generator import PdfReportGenerator
                    generator = PdfReportGenerator()
                    pdf_path = generator.generate_report(assessment, domain_name=target_arg)
                    print(f"\n[*] Complete Risk Assessment PDF exported to: {pdf_path}")
                except Exception as e:
                    print(f"\n[!] Failed to generate PDF Report: {e}")

            elif cmd == "interactive":
                print("You are already in interactive mode.")
            elif cmd == "compare":
                print("Side-by-side comparison is scheduled for Phase 3 rollout.")
            else:
                print(f"Unrecognized command: {cmd}. Type 'help' for options.")
                
        except KeyboardInterrupt:
            print("\nExiting...")
            break
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    # Add project root to sys.path if running directly
    current_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.abspath(os.path.join(current_dir, '..'))
    if parent_dir not in sys.path:
        sys.path.insert(0, parent_dir)
        
    run_interactive_cli()

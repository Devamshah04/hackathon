"""
Quantum Readiness Scanner Tool

Strands SDK tool that evaluates an asset's preparedness for PQC migration.
Returns a 0.0–1.0 score for the quantum_readiness parameter.

This checks:
  - Whether PQC algorithms are already deployed
  - Whether hybrid mode is enabled
  - Crypto agility (can algorithms be swapped without code changes?)
  - Whether a migration plan exists

Used by: WebApiAgent, IoTEdgeAgent, and other domain agents
"""

import json
from strands import tool


@tool
def scan_quantum_readiness(config: str) -> str:
    """
    Evaluate an asset's quantum readiness posture.

    Args:
        config: JSON string with fields:
            - pqc_algorithms_deployed: list of PQC algorithms in use
                (e.g., ["ML-KEM-768", "ML-DSA-65"])
            - hybrid_mode_enabled: bool (classical + PQC running together)
            - crypto_agile: bool (algorithms configurable without code changes)
            - migration_plan_exists: bool (documented PQC migration plan)
            - migration_plan_timeline: str (e.g., "Q2 2026", "" if none)
            - pqc_testing_done: bool (PQC algorithms tested in staging)
            - library_supports_pqc: bool (crypto library has PQC support)

    Returns:
        JSON string with:
        - score (0.0–1.0 for quantum_readiness parameter)
        - sub-scores and assessment details
    """
    try:
        cfg = json.loads(config)
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid JSON", "score": 0.0})

    pqc_deployed = cfg.get("pqc_algorithms_deployed", [])
    hybrid = cfg.get("hybrid_mode_enabled", False)
    agile = cfg.get("crypto_agile", False)
    plan_exists = cfg.get("migration_plan_exists", False)
    timeline = cfg.get("migration_plan_timeline", "")
    testing_done = cfg.get("pqc_testing_done", False)
    lib_supports = cfg.get("library_supports_pqc", False)

    findings = []
    sub_scores = {}

    # 1. PQC deployment status (35%)
    if pqc_deployed:
        deploy_score = 1.0
    elif hybrid:
        deploy_score = 0.8
    elif testing_done:
        deploy_score = 0.4
    else:
        deploy_score = 0.0
        findings.append({
            "component": "pqc_deployment",
            "risk": "HIGH",
            "recommendation": "Begin PQC algorithm testing and deployment",
        })
    sub_scores["pqc_deployed"] = deploy_score

    # 2. Crypto agility (25%)
    if agile:
        agility_score = 0.8 if not pqc_deployed else 1.0
    else:
        agility_score = 0.1
        findings.append({
            "component": "crypto_agility",
            "risk": "HIGH",
            "recommendation": "Refactor to use configurable algorithm selection (crypto agility)",
        })
    sub_scores["crypto_agility"] = agility_score

    # 3. Migration planning (20%)
    if plan_exists and timeline:
        plan_score = 0.9
    elif plan_exists:
        plan_score = 0.5
    else:
        plan_score = 0.0
        findings.append({
            "component": "migration_plan",
            "risk": "MEDIUM",
            "recommendation": "Create a PQC migration plan with timeline",
        })
    sub_scores["migration_plan"] = plan_score

    # 4. Library readiness (20%)
    if lib_supports and pqc_deployed:
        lib_score = 1.0
    elif lib_supports:
        lib_score = 0.6
    else:
        lib_score = 0.1
        findings.append({
            "component": "library_support",
            "risk": "MEDIUM",
            "recommendation": "Upgrade crypto libraries to versions with PQC support",
        })
    sub_scores["library_readiness"] = lib_score

    # Weighted composite
    composite = (
        deploy_score  * 0.35 +
        agility_score * 0.25 +
        plan_score    * 0.20 +
        lib_score     * 0.20
    )

    result = {
        "score": round(composite, 3),
        "sub_scores": sub_scores,
        "pqc_algorithms_in_use": pqc_deployed,
        "hybrid_mode": hybrid,
        "findings": findings,
        "total_findings": len(findings),
    }

    return json.dumps(result, indent=2)

"""
Key Management Scanner Tool

Strands SDK tool that evaluates key management practices for
quantum readiness. Returns a 0.0–1.0 score for the key_management parameter.

Used by: WebApiAgent, IoTEdgeAgent
"""

import json
from strands import tool


# ─── Key Storage Scores ──────────────────────────────────────────────────────
STORAGE_SCORES = {
    "hsm":                  1.0,   # Hardware Security Module
    "cloud_hsm":            0.9,   # Cloud-based HSM (e.g., AWS CloudHSM)
    "tee":                  0.85,  # Trusted Execution Environment
    "cloud_kms":            0.7,   # Cloud KMS (managed)
    "vault":                0.6,   # HashiCorp Vault or similar
    "encrypted_file":       0.3,   # Encrypted file on disk
    "environment_variable": 0.2,   # Environment vars
    "plaintext_config":     0.05,  # Plaintext in config files
    "hardcoded":            0.0,   # Hardcoded in source code
}

# ─── Rotation Policy Scores ─────────────────────────────────────────────────
ROTATION_SCORES = {
    "automatic_90days":     1.0,
    "automatic_180days":    0.85,
    "automatic_365days":    0.7,
    "manual_regular":       0.5,   # Manual but documented
    "manual_adhoc":         0.3,   # Manual, ad-hoc
    "no_rotation":          0.05,
}

# ─── Key Algorithm Scores ───────────────────────────────────────────────────
KEY_ALG_SCORES = {
    "ML-KEM":       1.0,
    "ML-DSA":       1.0,
    "AES-256":      0.9,   # Symmetric, quantum-resistant
    "AES-128":      0.6,
    "RSA-4096":     0.2,
    "RSA-2048":     0.1,
    "ECC-P384":     0.2,
    "ECC-P256":     0.15,
}


@tool
def scan_key_management(config: str) -> str:
    """
    Evaluate key management practices for quantum readiness.

    Assesses key storage mechanism, rotation policy, algorithm used,
    and overall key lifecycle management.

    Args:
        config: JSON string with fields:
            - storage_type: str (e.g., "hsm", "cloud_kms", "hardcoded")
            - rotation_policy: str (e.g., "automatic_90days", "no_rotation")
            - key_algorithm: str (e.g., "RSA-2048", "AES-256")
            - key_count: int (number of active keys)
            - separation_of_duties: bool (different people for key creation/use)
            - audit_logging: bool (key usage is logged)
            - backup_exists: bool (key backup/recovery plan)

    Returns:
        JSON string with:
        - score (0.0–1.0 for key_management parameter)
        - sub-scores for each component
        - findings and recommendations
    """
    try:
        cfg = json.loads(config)
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid JSON", "score": 0.0})

    storage = cfg.get("storage_type", "unknown")
    rotation = cfg.get("rotation_policy", "unknown")
    key_alg = cfg.get("key_algorithm", "unknown")
    separation = cfg.get("separation_of_duties", False)
    audit = cfg.get("audit_logging", False)
    backup = cfg.get("backup_exists", False)

    findings = []
    sub_scores = {}

    # 1. Storage security (35%)
    storage_score = STORAGE_SCORES.get(storage, 0.0)
    sub_scores["storage"] = storage_score
    if storage_score < 0.5:
        findings.append({
            "component": "key_storage",
            "value": storage,
            "risk": "CRITICAL" if storage_score <= 0.1 else "HIGH",
            "recommendation": "Migrate keys to HSM or Cloud KMS with access controls",
        })

    # 2. Rotation policy (25%)
    rotation_score = ROTATION_SCORES.get(rotation, 0.0)
    sub_scores["rotation"] = rotation_score
    if rotation_score < 0.5:
        findings.append({
            "component": "rotation_policy",
            "value": rotation,
            "risk": "HIGH",
            "recommendation": "Implement automatic key rotation (90-day cycle recommended)",
        })

    # 3. Key algorithm (25%)
    alg_score = KEY_ALG_SCORES.get(key_alg, 0.0)
    sub_scores["algorithm"] = alg_score
    if alg_score < 0.5:
        findings.append({
            "component": "key_algorithm",
            "value": key_alg,
            "risk": "CRITICAL" if alg_score <= 0.15 else "HIGH",
            "recommendation": "Migrate to PQC-safe key algorithms (ML-KEM/ML-DSA)",
        })

    # 4. Operational security (15%)
    ops_factors = [separation, audit, backup]
    ops_score = sum(1 for f in ops_factors if f) / len(ops_factors)
    sub_scores["operational"] = round(ops_score, 2)
    if not audit:
        findings.append({
            "component": "audit_logging",
            "risk": "MEDIUM",
            "recommendation": "Enable key usage audit logging",
        })

    # Weighted composite
    composite = (
        storage_score  * 0.35 +
        rotation_score * 0.25 +
        alg_score      * 0.25 +
        ops_score      * 0.15
    )

    result = {
        "score": round(composite, 3),
        "sub_scores": sub_scores,
        "findings": findings,
        "total_findings": len(findings),
    }

    return json.dumps(result, indent=2)

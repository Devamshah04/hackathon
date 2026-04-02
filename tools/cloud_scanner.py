"""
Cloud Scanner Tool

Strands SDK tool that evaluates cloud and storage encryption configurations
for quantum vulnerability, focusing on data-at-rest encryption and KMS
key management.

Addresses the "harvest now, decrypt later" (HNDL) threat where adversaries
capture encrypted data today for decryption with future quantum computers.

Used by: CloudStorageAgent
"""

import json
from strands import tool


# ─── Cloud Encryption Assessment ────────────────────────────────────────────
ENCRYPTION_ASSESSMENT = {
    "RSA-OAEP-2048": {
        "risk": "CRITICAL",
        "reason": "RSA-OAEP is a secure padding scheme but underlying RSA-2048 math is Q-vulnerable",
        "migration": "ML-KEM (FIPS 203) or RSA-OAEP with 4096-bit as interim",
        "hndl_risk": True,
    },
    "RSA-OAEP-4096": {
        "risk": "HIGH",
        "reason": "RSA-4096 delays quantum attack but does not prevent it; Shor's still applies",
        "migration": "ML-KEM (FIPS 203) for long-term quantum safety",
        "hndl_risk": True,
    },
    "AES-256-GCM": {
        "risk": "LOW",
        "reason": "AES-256 with 128-bit post-quantum effective strength — considered secure",
        "migration": "No change needed for symmetric layer; verify key wrapping is PQ-safe",
        "hndl_risk": False,
    },
    "AES-128-GCM": {
        "risk": "MEDIUM",
        "reason": "AES-128 reduced to 64-bit effective strength by Grover's — marginal for long-term data",
        "migration": "Upgrade to AES-256-GCM",
        "hndl_risk": False,
    },
}

# ─── KMS Key Type Assessment ────────────────────────────────────────────────
KMS_KEY_ASSESSMENT = {
    "RSA_2048": {"risk": "CRITICAL", "reason": "RSA-2048 KMS key broken by Shor's", "migration": "Rotate to AES-256 symmetric KMS key or await PQ-KMS support"},
    "RSA_4096": {"risk": "HIGH", "reason": "RSA-4096 KMS key vulnerable to Shor's", "migration": "Rotate to AES-256 symmetric KMS key or await PQ-KMS support"},
    "ECC_NIST_P256": {"risk": "CRITICAL", "reason": "ECC P-256 KMS key broken by Shor's", "migration": "Rotate to AES-256 symmetric KMS key"},
    "SYMMETRIC_DEFAULT": {"risk": "LOW", "reason": "AES-256 symmetric KMS key is quantum-resistant", "migration": "No change needed"},
}


@tool
def scan_cloud_encryption(config: str) -> str:
    """
    Analyze cloud/storage encryption configuration for quantum vulnerability.

    Evaluates data-at-rest encryption, KMS key types, and assesses the
    'harvest now, decrypt later' (HNDL) risk level.

    Args:
        config: JSON string with fields:
            - service: str (e.g., "S3", "EBS", "RDS", "DynamoDB")
            - encryption_algorithm: str (e.g., "RSA-OAEP-2048", "AES-256-GCM")
            - kms_key_type: str (e.g., "RSA_2048", "SYMMETRIC_DEFAULT")
            - data_classification: str (e.g., "public", "confidential", "top_secret")
            - retention_years: int (how long data must be kept encrypted)

    Returns:
        JSON string with quantum vulnerability assessment.
    """
    try:
        cfg = json.loads(config)
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid JSON in config"})

    service = cfg.get("service", "unknown")
    encryption_algo = cfg.get("encryption_algorithm", "unknown")
    kms_key_type = cfg.get("kms_key_type", "")
    data_class = cfg.get("data_classification", "unspecified")
    retention = cfg.get("retention_years", 0)

    result = {
        "service": service,
        "data_classification": data_class,
        "retention_years": retention,
        "findings": [],
    }

    # Assess encryption algorithm
    if encryption_algo in ENCRYPTION_ASSESSMENT:
        assessment = ENCRYPTION_ASSESSMENT[encryption_algo]
        finding = {
            "component": "data_encryption",
            "algorithm": encryption_algo,
            "risk_level": assessment["risk"],
            "reason": assessment["reason"],
            "migration": assessment["migration"],
            "hndl_vulnerable": assessment["hndl_risk"],
        }

        # Increase risk if long retention + HNDL vulnerable
        if assessment["hndl_risk"] and retention > 5:
            finding["risk_level"] = "CRITICAL"
            finding["hndl_warning"] = (
                f"Data retained for {retention} years with Q-vulnerable encryption — "
                "HIGH risk of 'harvest now, decrypt later' attack. Immediate migration recommended."
            )

        result["findings"].append(finding)

    # Assess KMS key type
    if kms_key_type and kms_key_type in KMS_KEY_ASSESSMENT:
        kms = KMS_KEY_ASSESSMENT[kms_key_type]
        result["findings"].append({
            "component": "kms_key",
            "key_type": kms_key_type,
            "risk_level": kms["risk"],
            "reason": kms["reason"],
            "migration": kms["migration"],
        })

    result["total_findings"] = len(result["findings"])

    return json.dumps(result, indent=2)

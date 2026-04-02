"""
JWT Scanner Tool

Strands SDK tool that decodes JWT token headers to identify quantum-vulnerable
signing algorithms (RS256, ES256, PS256, etc.) and recommends PQC replacements.

Used by: WebApiAgent
"""

import json
import re
from strands import tool


# ─── Vulnerability Database ──────────────────────────────────────────────────
VULNERABLE_ALGORITHMS = {
    "RS256": {"risk": "CRITICAL", "reason": "RSA-2048 broken by Shor's algorithm"},
    "RS384": {"risk": "CRITICAL", "reason": "RSA broken by Shor's algorithm"},
    "RS512": {"risk": "CRITICAL", "reason": "RSA broken by Shor's algorithm"},
    "ES256": {"risk": "HIGH",     "reason": "ECDSA broken by Shor's algorithm"},
    "ES384": {"risk": "HIGH",     "reason": "ECDSA broken by Shor's algorithm"},
    "ES512": {"risk": "HIGH",     "reason": "ECDSA broken by Shor's algorithm"},
    "PS256": {"risk": "CRITICAL", "reason": "RSA-PSS broken by Shor's algorithm"},
    "HS256": {"risk": "MEDIUM",   "reason": "Symmetric — safe but weak key sizes"},
    "HS512": {"risk": "LOW",      "reason": "Symmetric — quantum-resistant if key >= 256 bits"},
}

# ─── PQC Replacement Mapping ────────────────────────────────────────────────
PQC_REPLACEMENTS = {
    "RS256": {"algorithm": "ML-DSA-65", "standard": "FIPS 204"},
    "RS384": {"algorithm": "ML-DSA-65", "standard": "FIPS 204"},
    "RS512": {"algorithm": "ML-DSA-87", "standard": "FIPS 204"},
    "ES256": {"algorithm": "ML-DSA-44", "standard": "FIPS 204"},
    "ES384": {"algorithm": "ML-DSA-65", "standard": "FIPS 204"},
    "ES512": {"algorithm": "ML-DSA-87", "standard": "FIPS 204"},
    "PS256": {"algorithm": "ML-DSA-65", "standard": "FIPS 204"},
}


@tool
def scan_jwt(token: str) -> str:
    """
    Analyze a JWT token for quantum-vulnerable signing algorithms.

    Decodes the JWT header (without verification) to extract the 'alg'
    field and checks it against the known vulnerability database.

    Args:
        token: A JWT token string (header.payload.signature)

    Returns:
        JSON string with analysis results including:
        - algorithm found
        - risk level
        - vulnerability reason
        - recommended PQC replacement
    """
    try:
        # Decode header without verification
        parts = token.split(".")
        if len(parts) < 2:
            return json.dumps({"error": "Invalid JWT format — expected header.payload.signature"})

        # Pad base64 if needed
        header_b64 = parts[0]
        header_b64 += "=" * (4 - len(header_b64) % 4)

        import base64
        header = json.loads(base64.urlsafe_b64decode(header_b64))
        alg = header.get("alg", "unknown")

        result = {
            "token_header": header,
            "algorithm": alg,
            "quantum_vulnerable": alg in VULNERABLE_ALGORITHMS,
        }

        if alg in VULNERABLE_ALGORITHMS:
            vuln = VULNERABLE_ALGORITHMS[alg]
            result["risk_level"] = vuln["risk"]
            result["reason"] = vuln["reason"]

            if alg in PQC_REPLACEMENTS:
                replacement = PQC_REPLACEMENTS[alg]
                result["migration_target"] = {
                    "recommended_algorithm": replacement["algorithm"],
                    "standard": replacement["standard"],
                    "priority": "HIGH" if vuln["risk"] == "CRITICAL" else "MEDIUM",
                }
        else:
            result["risk_level"] = "INFO"
            result["reason"] = f"Algorithm '{alg}' not in vulnerability database"

        return json.dumps(result, indent=2)

    except Exception as e:
        return json.dumps({"error": f"JWT analysis failed: {str(e)}"})

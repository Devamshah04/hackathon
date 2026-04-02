"""
JWT Scanner Tool

Strands SDK tool that decodes JWT token headers to identify quantum-vulnerable
signing algorithms and returns a 0.0–1.0 score for the auth_token_crypto parameter.

Used by: WebApiAgent
"""

import json
import base64
from strands import tool


# ─── Algorithm Scoring (0.0–1.0 scale) ──────────────────────────────────────
# Higher = more secure / quantum-resistant
ALGORITHM_SCORES = {
    # PQC-safe
    "ML-DSA-44":  1.0,
    "ML-DSA-65":  1.0,
    "ML-DSA-87":  1.0,
    # Symmetric (quantum-resistant via key size)
    "HS512":      0.9,
    "HS384":      0.85,
    "HS256":      0.7,
    # ECC-based (Shor's vulnerable)
    "ES512":      0.3,
    "ES384":      0.25,
    "ES256":      0.2,
    # RSA-PSS (Shor's vulnerable)
    "PS512":      0.15,
    "PS384":      0.15,
    "PS256":      0.15,
    # RSA PKCS#1 (Shor's vulnerable, most common)
    "RS512":      0.1,
    "RS384":      0.1,
    "RS256":      0.1,
    # No signing
    "none":       0.0,
}

# ─── Risk Levels ─────────────────────────────────────────────────────────────
RISK_LEVELS = {
    "RS256": "CRITICAL", "RS384": "CRITICAL", "RS512": "CRITICAL",
    "PS256": "CRITICAL", "PS384": "CRITICAL", "PS512": "CRITICAL",
    "ES256": "HIGH",     "ES384": "HIGH",     "ES512": "HIGH",
    "HS256": "MEDIUM",   "HS384": "LOW",      "HS512": "LOW",
    "none":  "CRITICAL",
}

# ─── PQC Replacements ───────────────────────────────────────────────────────
PQC_REPLACEMENTS = {
    "RS256": {"algorithm": "ML-DSA-65", "standard": "FIPS 204"},
    "RS384": {"algorithm": "ML-DSA-65", "standard": "FIPS 204"},
    "RS512": {"algorithm": "ML-DSA-87", "standard": "FIPS 204"},
    "ES256": {"algorithm": "ML-DSA-44", "standard": "FIPS 204"},
    "ES384": {"algorithm": "ML-DSA-65", "standard": "FIPS 204"},
    "ES512": {"algorithm": "ML-DSA-87", "standard": "FIPS 204"},
    "PS256": {"algorithm": "ML-DSA-65", "standard": "FIPS 204"},
    "PS384": {"algorithm": "ML-DSA-65", "standard": "FIPS 204"},
    "PS512": {"algorithm": "ML-DSA-87", "standard": "FIPS 204"},
}


@tool
def scan_jwt(token: str) -> str:
    """
    Analyze a JWT token for quantum-vulnerable signing algorithms.

    Decodes the JWT header (without verification) to extract the 'alg'
    field, checks it against the vulnerability database, and returns
    a 0.0–1.0 security score.

    Args:
        token: A JWT token string (header.payload.signature)

    Returns:
        JSON string with analysis results including:
        - algorithm found
        - score (0.0–1.0 for auth_token_crypto parameter)
        - risk level (CRITICAL/HIGH/MEDIUM/LOW)
        - vulnerability reason
        - recommended PQC replacement
    """
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return json.dumps({
                "error": "Invalid JWT format",
                "score": 0.0,
            })

        # Decode header (no verification needed)
        header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_b64))
        alg = header.get("alg", "unknown")

        score = ALGORITHM_SCORES.get(alg, 0.0)
        risk_level = RISK_LEVELS.get(alg, "HIGH")

        result = {
            "token_header": header,
            "algorithm": alg,
            "score": score,
            "quantum_vulnerable": score < 0.7,  # symmetric HS256+ are safe
            "risk_level": risk_level,
        }

        if score < 0.7:
            result["reason"] = f"Algorithm '{alg}' is vulnerable to quantum attack"
            if alg in PQC_REPLACEMENTS:
                result["migration_target"] = PQC_REPLACEMENTS[alg]
        else:
            result["reason"] = f"Algorithm '{alg}' is quantum-resistant"

        return json.dumps(result, indent=2)

    except Exception as e:
        return json.dumps({"error": f"JWT analysis failed: {str(e)}", "score": 0.0})

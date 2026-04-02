"""
OAuth/OIDC Scanner Tool

Strands SDK tool that audits OAuth/OIDC configurations for quantum-vulnerable
crypto and returns a 0.0–1.0 score for the oauth_oidc parameter.

Used by: WebApiAgent
"""

import json
from strands import tool


# ─── Scoring Rules ───────────────────────────────────────────────────────────
# Factors that contribute to the OAuth/OIDC score:
#   - Token signing algorithm quality
#   - PKCE support (modern best practice)
#   - Grant type security
#   - JWKS key type safety

SIGNING_ALG_SCORES = {
    "ML-DSA-65": 1.0, "ML-DSA-44": 1.0, "ML-DSA-87": 1.0,
    "HS512": 0.8, "HS384": 0.75, "HS256": 0.6,
    "ES512": 0.3, "ES384": 0.25, "ES256": 0.2,
    "RS512": 0.1, "RS384": 0.1, "RS256": 0.1,
    "PS256": 0.1, "PS384": 0.1, "PS512": 0.1,
}

GRANT_TYPE_SCORES = {
    "authorization_code": 0.9,
    "client_credentials": 0.8,
    "device_code": 0.7,
    "implicit": 0.2,          # deprecated, insecure
    "password": 0.1,          # deprecated, insecure
}


@tool
def scan_oauth_endpoint(config: str) -> str:
    """
    Audit an OAuth/OIDC endpoint configuration for quantum vulnerability.

    Evaluates the OAuth configuration including token signing algorithms,
    PKCE support, grant types, and JWKS key types. Returns a 0.0–1.0
    security score.

    Args:
        config: JSON string with fields:
            - endpoint_url: str (the OAuth provider URL)
            - signing_algorithms: list of algorithm strings (e.g., ["RS256", "ES256"])
            - grant_types_supported: list of grant type strings
            - pkce_supported: bool
            - jwks_key_types: list of key type strings (e.g., ["RSA", "EC"])
            - token_endpoint_auth_methods: list (e.g., ["client_secret_post"])

    Returns:
        JSON string with:
        - score (0.0–1.0 for oauth_oidc parameter)
        - findings list
        - migration recommendations
    """
    try:
        cfg = json.loads(config)
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid JSON in config", "score": 0.0})

    endpoint = cfg.get("endpoint_url", "unknown")
    signing_algs = cfg.get("signing_algorithms", [])
    grant_types = cfg.get("grant_types_supported", [])
    pkce = cfg.get("pkce_supported", False)
    jwks_key_types = cfg.get("jwks_key_types", [])

    findings = []
    sub_scores = {}

    # 1. Signing algorithm quality (40% of OAuth score)
    if signing_algs:
        alg_scores = [SIGNING_ALG_SCORES.get(alg, 0.0) for alg in signing_algs]
        # Use the WORST algorithm as the score (weakest link)
        alg_score = min(alg_scores)
        sub_scores["signing_algorithm"] = alg_score

        for alg in signing_algs:
            s = SIGNING_ALG_SCORES.get(alg, 0.0)
            if s < 0.5:
                findings.append({
                    "component": "signing_algorithm",
                    "algorithm": alg,
                    "risk": "CRITICAL" if s <= 0.1 else "HIGH",
                    "recommendation": "Migrate to ML-DSA (FIPS 204)",
                })
    else:
        alg_score = 0.0
        sub_scores["signing_algorithm"] = 0.0

    # 2. PKCE support (20% of OAuth score)
    pkce_score = 0.9 if pkce else 0.3
    sub_scores["pkce"] = pkce_score
    if not pkce:
        findings.append({
            "component": "pkce",
            "risk": "MEDIUM",
            "recommendation": "Enable PKCE for authorization code flows",
        })

    # 3. Grant type security (20% of OAuth score)
    if grant_types:
        gt_scores = [GRANT_TYPE_SCORES.get(gt, 0.5) for gt in grant_types]
        grant_score = min(gt_scores)  # weakest link
        sub_scores["grant_types"] = grant_score

        for gt in grant_types:
            if GRANT_TYPE_SCORES.get(gt, 1.0) < 0.3:
                findings.append({
                    "component": "grant_type",
                    "grant_type": gt,
                    "risk": "HIGH",
                    "recommendation": f"Deprecate '{gt}' grant type",
                })
    else:
        grant_score = 0.5
        sub_scores["grant_types"] = 0.5

    # 4. JWKS key type safety (20% of OAuth score)
    if jwks_key_types:
        q_vulnerable_types = {"RSA", "EC", "ECC", "OKP"}
        if any(kt.upper() in q_vulnerable_types for kt in jwks_key_types):
            jwks_score = 0.2
            findings.append({
                "component": "jwks_key_types",
                "key_types": jwks_key_types,
                "risk": "HIGH",
                "recommendation": "Plan JWKS key migration to PQC-safe key types",
            })
        else:
            jwks_score = 0.9
        sub_scores["jwks_keys"] = jwks_score
    else:
        jwks_score = 0.5
        sub_scores["jwks_keys"] = 0.5

    # Weighted composite
    composite = (
        alg_score   * 0.40 +
        pkce_score  * 0.20 +
        grant_score * 0.20 +
        jwks_score  * 0.20
    )

    result = {
        "endpoint": endpoint,
        "score": round(composite, 3),
        "sub_scores": sub_scores,
        "findings": findings,
        "total_findings": len(findings),
    }

    return json.dumps(result, indent=2)

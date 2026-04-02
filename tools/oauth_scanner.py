"""
OAuth Scanner Tool

Strands SDK tool that audits OAuth/OIDC discovery endpoints for
quantum-vulnerable crypto suites in token signing and key exchange.

Used by: WebApiAgent
"""

import json
from strands import tool


@tool
def scan_oauth_endpoint(endpoint_url: str, discovery_doc: str = "") -> str:
    """
    Audit an OAuth/OIDC discovery endpoint for quantum-vulnerable crypto.

    Analyzes the discovery document (/.well-known/openid-configuration)
    to check for insecure signing algorithms in:
      - id_token_signing_alg_values_supported
      - token_endpoint_auth_signing_alg_values_supported
      - jwks_uri key types

    Args:
        endpoint_url: The OAuth discovery endpoint URL
        discovery_doc: Optional pre-fetched discovery document JSON string.
                       If empty, the tool will note it needs to be fetched.

    Returns:
        JSON string with discovered vulnerabilities in the OAuth configuration.
    """
    vulnerable_algs = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256"}

    result = {
        "endpoint": endpoint_url,
        "findings": [],
    }

    try:
        if discovery_doc:
            doc = json.loads(discovery_doc)
        else:
            result["note"] = "Discovery document not provided — manual fetch required"
            return json.dumps(result, indent=2)

        # Check id_token signing algorithms
        id_token_algs = doc.get("id_token_signing_alg_values_supported", [])
        for alg in id_token_algs:
            if alg in vulnerable_algs:
                result["findings"].append({
                    "field": "id_token_signing_alg_values_supported",
                    "algorithm": alg,
                    "risk": "CRITICAL" if alg.startswith("RS") or alg.startswith("PS") else "HIGH",
                    "recommendation": "Migrate to ML-DSA (FIPS 204)",
                })

        # Check token endpoint auth signing algorithms
        auth_algs = doc.get("token_endpoint_auth_signing_alg_values_supported", [])
        for alg in auth_algs:
            if alg in vulnerable_algs:
                result["findings"].append({
                    "field": "token_endpoint_auth_signing_alg_values_supported",
                    "algorithm": alg,
                    "risk": "CRITICAL" if alg.startswith("RS") or alg.startswith("PS") else "HIGH",
                    "recommendation": "Migrate to ML-DSA (FIPS 204)",
                })

        # Check JWKS URI key types
        jwks_uri = doc.get("jwks_uri", "")
        if jwks_uri:
            result["jwks_uri"] = jwks_uri
            result["findings"].append({
                "field": "jwks_uri",
                "note": "JWKS endpoint detected — verify key types (RSA/EC) are quantum-safe",
                "risk": "MEDIUM",
                "recommendation": "Audit JWKS keys for RSA/EC and plan ML-KEM/ML-DSA migration",
            })

        result["total_vulnerabilities"] = len(result["findings"])

    except json.JSONDecodeError:
        result["error"] = "Failed to parse discovery document as JSON"
    except Exception as e:
        result["error"] = f"OAuth scan failed: {str(e)}"

    return json.dumps(result, indent=2)

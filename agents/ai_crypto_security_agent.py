# ai_crypto_security_agent.py

import ssl
import socket
from datetime import datetime

# =========================================================
# 1. DATA COLLECTION (TLS + CERTIFICATE)
# =========================================================

def get_tls_info(host, port=443):
    context = ssl.create_default_context()

    with socket.create_connection((host, port)) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
            cipher = ssock.cipher()
            tls_version = ssock.version()

    return {
        "tls_version": tls_version,
        "cipher": cipher[0],
        "public_key_algo": cert.get("subjectPublicKeyInfo", "Unknown"),
        "cert": cert
    }


# =========================================================
# 2. FEATURE EXTRACTION
# =========================================================

def extract_features(tls_data):
    cipher = tls_data["cipher"]

    # Basic parsing
    if "AES256" in cipher:
        symmetric = "AES-256"
    elif "AES128" in cipher:
        symmetric = "AES-128"
    elif "CHACHA20" in cipher:
        symmetric = "CHACHA20"
    else:
        symmetric = "UNKNOWN"

    if "ECDHE" in cipher:
        key_exchange = "ECDHE"
    elif "RSA" in cipher:
        key_exchange = "RSA"
    else:
        key_exchange = "UNKNOWN"

    return {
        "tls_version": tls_data["tls_version"],
        "symmetric": symmetric,
        "key_exchange": key_exchange,
        "public_key": "RSA-2048",  # Placeholder (extend with real parsing)
        "hash": "SHA-256",         # Placeholder
        "pqc": False
    }


# =========================================================
# 3. SCORING FUNCTIONS
# =========================================================

def score_crypto(features):
    score = 0

    # Public Key
    if features["public_key"] == "RSA-2048":
        score += 60
    elif features["public_key"] == "KYBER":
        score += 100

    # Symmetric
    if features["symmetric"] == "AES-256":
        score += 100
    elif features["symmetric"] == "AES-128":
        score += 70
    elif features["symmetric"] == "CHACHA20":
        score += 95

    # Hash
    if features["hash"] == "SHA-256":
        score += 100

    return score / 3


def score_protocol(features):
    score = 0

    # TLS Version
    if features["tls_version"] == "TLSv1.3":
        score += 100
    elif features["tls_version"] == "TLSv1.2":
        score += 70
    else:
        score += 30

    # Cipher quality
    if features["symmetric"] in ["AES-256", "CHACHA20"]:
        score += 100
    else:
        score += 60

    # Key exchange
    if features["key_exchange"] == "ECDHE":
        score += 100
    else:
        score += 50

    return score / 3


def score_quantum(features):
    if features["pqc"]:
        return 100
    else:
        return 30


def score_implementation():
    return 70  # Placeholder (extend later)


def score_key_management():
    return 60  # Placeholder


def score_compliance():
    return 50  # Placeholder


# =========================================================
# 4. FINAL SCORING ENGINE
# =========================================================

def calculate_final_score(features):
    crypto = score_crypto(features)
    protocol = score_protocol(features)
    implementation = score_implementation()
    key_mgmt = score_key_management()
    compliance = score_compliance()
    quantum = score_quantum(features)

    final_score = (
        crypto * 0.3 +
        protocol * 0.2 +
        implementation * 0.2 +
        key_mgmt * 0.1 +
        compliance * 0.1 +
        quantum * 0.1
    )

    return {
        "crypto": crypto,
        "protocol": protocol,
        "implementation": implementation,
        "key_management": key_mgmt,
        "compliance": compliance,
        "quantum": quantum,
        "final_score": round(final_score, 2)
    }


# =========================================================
# 5. DECISION ENGINE
# =========================================================

def get_verdict(score):
    if score >= 90:
        return "✅ Highly Secure (Quantum Ready)"
    elif score >= 70:
        return "⚠️ Secure but Not Quantum Safe"
    elif score >= 50:
        return "❗ Moderate Risk"
    else:
        return "❌ Insecure"


# =========================================================
# 6. MAIN AI AGENT FUNCTION
# =========================================================

def analyze_system(host):
    print(f"\n🔍 Analyzing {host}...\n")

    try:
        tls_data = get_tls_info(host)
        features = extract_features(tls_data)
        scores = calculate_final_score(features)
        verdict = get_verdict(scores["final_score"])

        print("=== FEATURES ===")
        for k, v in features.items():
            print(f"{k}: {v}")

        print("\n=== SCORES ===")
        for k, v in scores.items():
            print(f"{k}: {v}")

        print("\n=== FINAL VERDICT ===")
        print(verdict)

    except Exception as e:
        print(f"Error analyzing system: {e}")


# =========================================================
# 7. RUN
# =========================================================

if __name__ == "__main__":
    target = input("Enter domain (e.g., google.com): ")
    analyze_system(target)
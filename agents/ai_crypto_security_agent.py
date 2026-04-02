# pqc_ai_agent_final.py

import os
import re
import ssl
import socket
import subprocess
import tempfile
from urllib.parse import urlparse

# =========================================================
# AI ANALYSIS (ROBUST WITH FALLBACK MODELS)
# =========================================================

def _deterministic_analysis(prompt):
    """Rule-based fallback analysis when Bedrock is unavailable."""
    lines = []
    p = prompt.upper()

    if "TLSV1.3" in p or "TLS 1.3" in p:
        lines.append("TLS 1.3 detected — transport layer is classically secure.")
        lines.append("RISK: No Post-Quantum key exchange detected. Vulnerable to harvest-now-decrypt-later (HNDL) attacks.")
        lines.append("RECOMMENDATION: Migrate to TLS 1.3 hybrid PQC (X25519+ML-KEM-768, FIPS 203).")
    elif "TLS" in p:
        lines.append("TLS 1.2 or older detected — outdated protocol with weak cipher negotiation.")
        lines.append("RISK: Vulnerable to both classical and quantum attacks.")
        lines.append("RECOMMENDATION: Upgrade to TLS 1.3 with hybrid PQC key exchange immediately.")

    if "RSA" in p:
        lines.append("RISK: RSA detected — broken by Shor's algorithm on a sufficiently large quantum computer.")
        lines.append("RECOMMENDATION: Replace RSA with ML-KEM (key exchange, FIPS 203) or ML-DSA (signatures, FIPS 204).")

    if "MD5" in p:
        lines.append("CRITICAL: MD5 detected — cryptographically broken, collision attacks are trivial.")
        lines.append("RECOMMENDATION: Replace MD5 with SHA-256 or SHA-3 immediately.")

    if "SHA1" in p:
        lines.append("HIGH: SHA-1 detected — deprecated and vulnerable to collision attacks.")
        lines.append("RECOMMENDATION: Migrate to SHA-256 or SHA-3.")

    if "KYBER" in p or "ML-KEM" in p or "DILITHIUM" in p or "ML-DSA" in p:
        lines.append("PQC algorithm detected — good quantum readiness posture.")

    if not lines:
        lines.append("No specific vulnerabilities identified from scan data.")
        lines.append("RECOMMENDATION: Conduct a full cryptographic inventory and develop a PQC migration roadmap.")

    return "\n".join(lines)


def ai_analysis(prompt):
    models_to_try = [
        "anthropic.claude-3-haiku-20240307-v1:0",
        "anthropic.claude-3-sonnet-20240229-v1:0",
    ]

    for model_id in models_to_try:
        try:
            from strands import Agent
            from strands.models.bedrock import BedrockModel

            model = BedrockModel(
                model_id=model_id,
                region_name=os.getenv("AWS_REGION", "us-east-1"),
            )
            agent = Agent(model=model)
            response = agent(prompt)

            if hasattr(response, "message"):
                return response.message.get("content", [{}])[0].get("text", "")
            return str(response)

        except Exception:
            continue

    return _deterministic_analysis(prompt)


# =========================================================
# MEMORY
# =========================================================
memory = {"results": []}

# =========================================================
# CRYPTO PATTERNS
# =========================================================
CRYPTO_PATTERNS = {
    "AES": r"AES",
    "RSA": r"RSA",
    "MD5": r"MD5",
    "SHA1": r"SHA1",
    "SHA256": r"SHA256",
    "KYBER": r"KYBER",
    "DILITHIUM": r"DILITHIUM",
}

SUPPORTED_EXT = (".py", ".c", ".cpp", ".h", ".java", ".js", ".go", ".rs")

# =========================================================
# GITHUB SCAN
# =========================================================
def clone_repo(url):
    temp = tempfile.mkdtemp()
    subprocess.run(["git", "clone", url, temp],
                   stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL)
    return temp

def scan_repo(path):
    algos = set()

    for root, _, files in os.walk(path):
        for f in files:
            if f.endswith(SUPPORTED_EXT):
                try:
                    content = open(os.path.join(root, f), errors="ignore").read()
                    for k, v in CRYPTO_PATTERNS.items():
                        if re.search(v, content):
                            algos.add(k)
                except:
                    pass

    return list(algos)

# =========================================================
# WEB SCAN
# =========================================================
def scan_web(url):
    host = urlparse(url).hostname if "://" in url else url
    context = ssl.create_default_context()

    with socket.create_connection((host, 443), timeout=5) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            return {
                "tls": ssock.version(),
                "cipher": ssock.cipher()[0]
            }

# =========================================================
# SCORING
# =========================================================
def score_github(algos):
    score = 100
    reasons = []

    if "MD5" in algos:
        score -= 40; reasons.append("MD5 → broken")
    if "SHA1" in algos:
        score -= 30; reasons.append("SHA1 → weak")
    if "RSA" in algos:
        score -= 10; reasons.append("RSA → quantum risk")
    if "KYBER" in algos:
        score += 10; reasons.append("PQC detected")

    return max(score, 0), reasons


def score_web(data):
    score = 0
    reasons = []

    if data["tls"] == "TLSv1.3":
        score += 100; reasons.append("TLS 1.3 secure")
    else:
        score += 70; reasons.append("TLS 1.2 outdated")

    reasons.append("No PQC → quantum vulnerable")

    final = score * 0.6 + 40 * 0.4
    return final, reasons

# =========================================================
# ANALYSIS
# =========================================================
def analyze_target(target):
    try:
        if "github.com" in target:
            print("📦 Cloning repository...")
            path = clone_repo(target)
            algos = scan_repo(path)

            score, reasons = score_github(algos)

            prompt = f"""
Analyze PQC risks:

Algorithms: {algos}
Score: {score}

Explain risks and migration steps.
"""
            ai_text = ai_analysis(prompt)

            return {
                "asset": target,
                "type": "github",
                "algorithms": algos,
                "score": score,
                "reasons": reasons,
                "ai": ai_text
            }

        else:
            print("🌐 Scanning web domain...")
            data = scan_web(target)

            score, reasons = score_web(data)

            prompt = f"""
TLS: {data['tls']}
Cipher: {data['cipher']}
Score: {score}

Explain risks and PQC readiness.
"""
            ai_text = ai_analysis(prompt)

            return {
                "asset": target,
                "type": "web",
                "score": score,
                "reasons": reasons,
                "ai": ai_text
            }

    except Exception as e:
        return {
            "asset": target,
            "score": 0,
            "reasons": [str(e)],
            "ai": ""
        }

# =========================================================
# RANKING
# =========================================================
def rank_assets(results):
    return sorted(results, key=lambda x: x["score"])

# =========================================================
# CLI
# =========================================================
def run_agent():
    print("""
╔══════════════════════════════════════╗
║   PQC AI AGENT (AUTO MODEL SWITCH)   ║
╚══════════════════════════════════════╝

Commands:
 scan <targets>
 report
 exit
""")

    while True:
        cmd = input("\nYou: ").strip()

        if cmd == "exit":
            break

        elif cmd.startswith("scan"):
            targets = cmd.split()[1:]

            for t in targets:
                print(f"\n🔍 Scanning: {t}")
                res = analyze_target(t)
                memory["results"].append(res)

                print("Score:", round(res["score"], 2))
                print("Reasons:", res["reasons"])

                print("\n🤖 AI Analysis:\n", res["ai"][:400])

        elif cmd == "report":
            ranked = rank_assets(memory["results"])

            print("\n=== RANKING ===")
            for i, r in enumerate(ranked, 1):
                print(f"{i}. {r['asset']} → {round(r['score'],2)}")

        else:
            print("Unknown command")

# =========================================================
# RUN
# =========================================================
if __name__ == "__main__":
    run_agent()

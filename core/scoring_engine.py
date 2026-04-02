"""
Scoring Engine — Weighted scoring model for PQC readiness assessment.

Implements the scoring formula from the AI Agent Framework PDF, adapted
per infrastructure domain. Converts 5 parameter scores (0.0–1.0) into
a final 1–10 rating and generates a priority-ranked output.

Architecture:
  raw scores (0.0–1.0)  →  weighted sum  →  final rating (1–10)  →  verdict

This module is purely deterministic — no LLM calls, no AWS dependency.
"""

from __future__ import annotations
import math
from dataclasses import dataclass, field, asdict
from typing import Optional


# ─── Weight Profiles Per Domain ──────────────────────────────────────────────
# Each domain has its own weighting. Only web_api is defined here for now;
# other agents can register their own profiles.

WEIGHT_PROFILES: dict[str, dict[str, float]] = {
    "web_api": {
        "auth_token_crypto": 0.30,
        "tls_transport":     0.25,
        "oauth_oidc":        0.20,
        "key_management":    0.15,
        "quantum_readiness": 0.10,
    },
    "iot_edge": {
        "firmware_signing":  0.30,
        "device_longevity":  0.25,
        "ota_security":      0.20,
        "key_management":    0.15,
        "quantum_readiness": 0.10,
    },
}


# ─── Decision Criteria ───────────────────────────────────────────────────────
VERDICTS = [
    (9, 10, "Quantum-Ready",              "✅ No immediate action needed"),
    (7,  8, "Secure — needs PQC transition", "⚡ Plan migration within 12 months"),
    (5,  6, "Moderate Risk",              "⚠️ Prioritize migration within 6 months"),
    (3,  4, "High Risk",                  "🔴 Urgent migration required"),
    (1,  2, "Critical / Insecure",        "🚨 Immediate action — HNDL exposed"),
]


def get_verdict(rating: int) -> tuple[str, str]:
    """Return (verdict_label, action_text) for a given 1–10 rating."""
    for low, high, label, action in VERDICTS:
        if low <= rating <= high:
            return label, action
    return "Unknown", "Review manually"


# ─── Data Classes ────────────────────────────────────────────────────────────

@dataclass
class ParameterScore:
    """Score for a single evaluation parameter."""
    name: str
    score: float | None    # 0.0 – 1.0 or None if N/A
    weight: float          # from the weight profile
    details: str = ""      # human-readable explanation
    sub_scores: dict = field(default_factory=dict)   # optional breakdown

    @property
    def is_available(self) -> bool:
        return self.score is not None

    @property
    def weighted(self) -> float:
        return (self.score * self.weight) if self.is_available else 0.0

    def to_dict(self) -> dict:
        return {
            "score": round(self.score, 3) if self.is_available else None,
            "weight": self.weight,
            "weighted_score": round(self.weighted, 4),
            "details": self.details,
            **({"sub_scores": self.sub_scores} if self.sub_scores else {}),
        }


@dataclass
class AssetRating:
    """Final rating for a single infrastructure asset."""
    asset: str
    domain: str
    parameter_scores: list[ParameterScore]
    findings: list[dict] = field(default_factory=list)
    migration_recommendations: list[str] = field(default_factory=list)

    @property
    def weighted_sum(self) -> float:
        total_weight = sum(p.weight for p in self.parameter_scores if p.is_available)
        raw_weighted_sum = sum(p.weighted for p in self.parameter_scores if p.is_available)
        
        if total_weight == 0.0:
            return 0.0
            
        # Normalize the score based on the available weights, scaling it to 1.0
        return raw_weighted_sum / total_weight

    @property
    def rating(self) -> int:
        """Convert weighted sum (0.0–1.0) to 1–10 scale."""
        raw = self.weighted_sum * 10
        # Clamp to 1–10
        return max(1, min(10, math.ceil(raw)))

    @property
    def verdict(self) -> str:
        return get_verdict(self.rating)[0]

    @property
    def action(self) -> str:
        return get_verdict(self.rating)[1]

    def to_dict(self) -> dict:
        return {
            "asset": self.asset,
            "domain": self.domain,
            "rating": self.rating,
            "verdict": self.verdict,
            "action": self.action,
            "weighted_score": round(self.weighted_sum, 4),
            "parameter_scores": {
                p.name: p.to_dict() for p in self.parameter_scores
            },
            "findings": self.findings,
            "migration_recommendations": self.migration_recommendations,
        }


# ─── Scoring Engine ──────────────────────────────────────────────────────────

class ScoringEngine:
    """
    Deterministic scoring engine.

    Takes raw parameter scores, applies domain-specific weights,
    and produces a 1–10 rating with verdict + priority ranking.

    Works entirely offline — no AWS, no LLM.
    """

    def __init__(self, domain: str = "web_api"):
        if domain not in WEIGHT_PROFILES:
            raise ValueError(f"Unknown domain '{domain}'. Available: {list(WEIGHT_PROFILES.keys())}")
        self.domain = domain
        self.weights = WEIGHT_PROFILES[domain]

    def score_asset(
        self,
        asset: str,
        scores: dict[str, tuple[float | None, str]],
        findings: list[dict] | None = None,
        recommendations: list[str] | None = None,
    ) -> AssetRating:
        """
        Score a single asset across all parameters. Dynamic weighting skips None scores.

        Args:
            asset: Asset identifier (e.g., "api.example.com")
            scores: Dict of {param_name: (score_float or None, details_str)}
            findings: Optional list of raw findings dicts
            recommendations: Optional list of migration recommendation strings

        Returns:
            AssetRating with rating, verdict, and full breakdown.
        """
        param_scores = []
        for param_name, weight in self.weights.items():
            if param_name in scores:
                score_val, details = scores[param_name]
            else:
                score_val, details = None, "Not assessed"

            param_scores.append(ParameterScore(
                name=param_name,
                score=max(0.0, min(1.0, score_val)) if score_val is not None else None,
                weight=weight,
                details=details,
            ))

        return AssetRating(
            asset=asset,
            domain=self.domain,
            parameter_scores=param_scores,
            findings=findings or [],
            migration_recommendations=recommendations or [],
        )

    def rank_assets(self, ratings: list[AssetRating]) -> list[dict]:
        """
        Sort assets by rating (ascending = worst first = highest migration priority).

        Returns list of dicts with priority_rank added.
        """
        sorted_ratings = sorted(ratings, key=lambda r: r.rating)
        ranked = []
        for rank, rating in enumerate(sorted_ratings, 1):
            entry = rating.to_dict()
            entry["priority_rank"] = rank
            ranked.append(entry)
        return ranked

    def summary_table(self, ranked: list[dict]) -> str:
        """Generate a human-readable priority ranking table."""
        lines = [
            "Priority │ Asset                    │ Rating │ Verdict",
            "─────────│──────────────────────────│────────│──────────────────────────",
        ]
        for item in ranked:
            lines.append(
                f"{item['priority_rank']:^9}│ {item['asset']:<24} │ {item['rating']:>2}/10  │ {item['verdict']}"
            )
        return "\n".join(lines)

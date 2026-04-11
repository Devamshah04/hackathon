"""
Enhanced Scoring Engine — 10-parameter weighted scoring with regional compliance.

Implements expanded scoring model with 10 parameters per domain, regional weight
modifiers, and 100-point scale for comprehensive PQC readiness assessment.
"""

from __future__ import annotations
import math
from dataclasses import dataclass, field
from typing import Optional
from .enhanced_region_standards import get_enhanced_region_profile

# Enhanced Weight Profiles (10 parameters each)
ENHANCED_WEIGHT_PROFILES: dict[str, dict[str, float]] = {
    "web_api": {
        "auth_token_crypto": 0.15,
        "tls_transport": 0.12,
        "oauth_oidc": 0.10,
        "key_management": 0.12,
        "quantum_readiness": 0.08,
        "certificate_security": 0.10,
        "api_encryption": 0.08,
        "session_management": 0.08,
        "data_at_rest": 0.09,
        "regulatory_compliance": 0.08,
    },
    "iot_edge": {
        "firmware_signing": 0.15,
        "device_longevity": 0.12,
        "ota_security": 0.10,
        "key_management": 0.12,
        "quantum_readiness": 0.08,
        "hardware_security": 0.10,
        "communication_protocol": 0.08,
        "certificate_security": 0.08,
        "data_at_rest": 0.09,
        "regulatory_compliance": 0.08,
    },
    "cloud_storage": {
        "data_at_rest_encryption": 0.15,
        "key_management_service": 0.12,
        "backup_archive": 0.10,
        "data_transfer_encryption": 0.12,
        "quantum_readiness": 0.08,
        "access_control_iam": 0.10,
        "certificate_security": 0.08,
        "compliance_auditing": 0.08,
        "multi_cloud_security": 0.09,
        "regulatory_compliance": 0.08,
    },
    "algorithms_network": {
        "tls_transport": 0.15,
        "public_key_crypto": 0.12,
        "symmetric_crypto": 0.10,
        "network_protocols": 0.12,
        "quantum_readiness": 0.08,
        "certificate_security": 0.10,
        "hash_algorithms": 0.08,
        "key_management": 0.08,
        "code_crypto_audit": 0.09,
        "regulatory_compliance": 0.08,
    },
}

# Enhanced Decision Criteria (100-point scale)
ENHANCED_VERDICTS = [
    (90, 100, "Quantum-Ready", "✅ Excellent - No immediate action needed"),
    (80, 89, "Secure - Minor PQC gaps", "⚡ Plan migration within 12 months"),
    (70, 79, "Good - Needs PQC transition", "⚠️ Prioritize migration within 9 months"),
    (60, 69, "Moderate Risk", "🔶 Urgent migration within 6 months"),
    (50, 59, "High Risk", "🔴 Critical migration within 3 months"),
    (40, 49, "Critical Risk", "🚨 Immediate action - HNDL exposed"),
    (0, 39, "Insecure", "💀 Emergency migration required"),
]

def get_enhanced_verdict(score: int) -> tuple[str, str]:
    """Return (verdict_label, action_text) for a given 0-100 score."""
    for low, high, label, action in ENHANCED_VERDICTS:
        if low <= score <= high:
            return label, action
    return "Unknown", "Review manually"

@dataclass
class EnhancedParameterScore:
    """Enhanced score for a single evaluation parameter with regional weighting."""
    name: str
    score: float | None    # 0.0 – 1.0 or None if N/A
    base_weight: float     # from the weight profile
    region_modifier: float = 1.0  # regional weight modifier
    details: str = ""      # human-readable explanation
    sub_scores: dict = field(default_factory=dict)

    @property
    def effective_weight(self) -> float:
        return self.base_weight * self.region_modifier

    @property
    def is_available(self) -> bool:
        return self.score is not None

    @property
    def weighted(self) -> float:
        return (self.score * self.effective_weight) if self.is_available else 0.0

    def to_dict(self) -> dict:
        return {
            "score": round(self.score, 3) if self.is_available else None,
            "base_weight": self.base_weight,
            "region_modifier": self.region_modifier,
            "effective_weight": round(self.effective_weight, 3),
            "weighted_score": round(self.weighted, 4),
            "details": self.details,
            **({
                "sub_scores": self.sub_scores
            } if self.sub_scores else {}),
        }

@dataclass
class EnhancedAssetRating:
    """Enhanced rating for a single infrastructure asset with 100-point scale."""
    asset: str
    domain: str
    region: str
    parameter_scores: list[EnhancedParameterScore]
    findings: list[dict] = field(default_factory=list)
    migration_recommendations: list[str] = field(default_factory=list)

    @property
    def weighted_sum(self) -> float:
        total_weight = sum(p.effective_weight for p in self.parameter_scores if p.is_available)
        raw_weighted_sum = sum(p.weighted for p in self.parameter_scores if p.is_available)
        
        if total_weight == 0.0:
            return 0.0
            
        return raw_weighted_sum / total_weight

    @property
    def score_100(self) -> int:
        """Convert weighted sum (0.0–1.0) to 0–100 scale."""
        raw = self.weighted_sum * 100
        return max(0, min(100, round(raw)))

    @property
    def verdict(self) -> str:
        return get_enhanced_verdict(self.score_100)[0]

    @property
    def action(self) -> str:
        return get_enhanced_verdict(self.score_100)[1]

    @property
    def priority_level(self) -> str:
        """Dynamic priority based on score."""
        if self.score_100 >= 80:
            return "LOW"
        elif self.score_100 >= 60:
            return "MEDIUM"
        elif self.score_100 >= 40:
            return "HIGH"
        else:
            return "CRITICAL"

    def to_dict(self) -> dict:
        return {
            "asset": self.asset,
            "domain": self.domain,
            "region": self.region,
            "score_100": self.score_100,
            "verdict": self.verdict,
            "action": self.action,
            "priority_level": self.priority_level,
            "weighted_score": round(self.weighted_sum, 4),
            "parameter_scores": {
                p.name: p.to_dict() for p in self.parameter_scores
            },
            "findings": self.findings,
            "migration_recommendations": self.migration_recommendations,
        }

class EnhancedScoringEngine:
    """Enhanced scoring engine with regional compliance and 100-point scale."""

    def __init__(self, domain: str = "web_api", region: str = "US"):
        if domain not in ENHANCED_WEIGHT_PROFILES:
            raise ValueError(f"Unknown domain '{domain}'. Available: {list(ENHANCED_WEIGHT_PROFILES.keys())}")
        
        self.domain = domain
        self.region = region.upper()
        self.base_weights = ENHANCED_WEIGHT_PROFILES[domain]
        self.region_profile = get_enhanced_region_profile(self.region)

    def score_asset(
        self,
        asset: str,
        scores: dict[str, tuple[float | None, str]],
        findings: list[dict] | None = None,
        recommendations: list[str] | None = None,
    ) -> EnhancedAssetRating:
        """Score a single asset with regional weighting and 100-point scale."""
        param_scores = []
        region_modifiers = self.region_profile.get("weight_modifiers", {})
        
        for param_name, base_weight in self.base_weights.items():
            if param_name in scores:
                score_val, details = scores[param_name]
            else:
                score_val, details = None, "Not assessed"

            region_modifier = region_modifiers.get(param_name, 1.0)
            
            param_scores.append(EnhancedParameterScore(
                name=param_name,
                score=max(0.0, min(1.0, score_val)) if score_val is not None else None,
                base_weight=base_weight,
                region_modifier=region_modifier,
                details=details,
            ))

        return EnhancedAssetRating(
            asset=asset,
            domain=self.domain,
            region=self.region,
            parameter_scores=param_scores,
            findings=findings or [],
            migration_recommendations=recommendations or [],
        )

    def score_asset_dynamic(
        self,
        asset: str,
        scores: dict[str, tuple[float, str]],
        findings: list[dict] | None = None,
        recommendations: list[str] | None = None,
    ) -> EnhancedAssetRating:
        """
        Score an asset with a fully dynamic parameter set.

        Unlike score_asset(), this method does NOT use a predefined weight
        profile.  It distributes weight equally across all provided
        parameters and applies regional modifiers where the parameter name
        matches a key in the region profile.

        Args:
            asset:   Target asset name.
            scores:  {param_name: (score_0_to_1, details_str)} — only REAL
                     assessed parameters.  Do NOT include None scores; simply
                     omit unassessed parameters from the dict.
            findings:          Raw finding dicts from scanner tools.
            recommendations:   Human-readable migration recommendations.

        Returns:
            EnhancedAssetRating (identical type to score_asset, works with
            the same PDF/CLI/JSON pipelines).
        """
        if not scores:
            # Nothing to score — return a zero-rated entry
            return EnhancedAssetRating(
                asset=asset,
                domain=self.domain,
                region=self.region,
                parameter_scores=[],
                findings=findings or [],
                migration_recommendations=recommendations or [],
            )

        n = len(scores)
        equal_weight = 1.0 / n
        region_modifiers = self.region_profile.get("weight_modifiers", {})

        param_scores = []
        for param_name, (score_val, details) in scores.items():
            region_modifier = region_modifiers.get(param_name, 1.0)
            param_scores.append(EnhancedParameterScore(
                name=param_name,
                score=max(0.0, min(1.0, score_val)),
                base_weight=round(equal_weight, 4),
                region_modifier=region_modifier,
                details=details,
            ))

        return EnhancedAssetRating(
            asset=asset,
            domain=self.domain,
            region=self.region,
            parameter_scores=param_scores,
            findings=findings or [],
            migration_recommendations=recommendations or [],
        )

    def rank_assets(self, ratings: list[EnhancedAssetRating]) -> list[dict]:
        """Sort assets by score (ascending = worst first = highest migration priority)."""
        sorted_ratings = sorted(ratings, key=lambda r: r.score_100)
        ranked = []
        for rank, rating in enumerate(sorted_ratings, 1):
            entry = rating.to_dict()
            entry["priority_rank"] = rank
            ranked.append(entry)
        return ranked

    def summary_table(self, ranked: list[dict]) -> str:
        """Generate enhanced priority ranking table with 100-point scores."""
        lines = [
            "Priority │ Asset                    │ Score │ Priority │ Verdict",
            "─────────│──────────────────────────│───────│──────────│──────────────────────────",
        ]
        for item in ranked:
            lines.append(
                f"{item['priority_rank']:^9}│ {item['asset']:<24} │ {item['score_100']:>3}/100│ {item['priority_level']:<8} │ {item['verdict']}"
            )
        return "\n".join(lines)
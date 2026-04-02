"""
Learning Store — Experience storage for RL-style agent improvement.

Implements a lightweight reinforcement learning loop:
  1. Agent scans assets and produces scores
  2. Results are stored as "experiences" in a local JSON file
  3. On subsequent runs, the agent loads past experiences as context
  4. The LLM uses historical patterns to refine its analysis
  5. Optionally, human feedback can be attached to adjust future scoring

This creates an improvement signal without traditional training:
  - No model fine-tuning required
  - Works with any LLM backend (Bedrock, local, etc.)
  - Fully local — no AWS dependency for the learning loop
  - Portable — experience file can be shared across deployments

Storage format:
  data/learning/{agent_name}_experiences.json
"""

from __future__ import annotations
import json
import os
import time
from datetime import datetime, timezone
from typing import Optional
from pathlib import Path


# ─── Default Paths ───────────────────────────────────────────────────────────
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LEARNING_DIR = _PROJECT_ROOT / "data" / "learning"


class LearningStore:
    """
    Local experience store for agent learning.

    Stores past scan results and optional feedback so the agent
    can improve its analysis over time (in-context RL).
    """

    def __init__(self, agent_name: str, store_dir: str | Path | None = None):
        self.agent_name = agent_name
        self.store_dir = Path(store_dir) if store_dir else DEFAULT_LEARNING_DIR
        self.store_dir.mkdir(parents=True, exist_ok=True)
        self.filepath = self.store_dir / f"{agent_name}_experiences.json"
        self._experiences: list[dict] = self._load()

    # ── Persistence ─────────────────────────────────────────────────────────

    def _load(self) -> list[dict]:
        """Load experiences from disk."""
        if self.filepath.exists():
            try:
                with open(self.filepath, "r") as f:
                    data = json.load(f)
                return data if isinstance(data, list) else []
            except (json.JSONDecodeError, IOError):
                return []
        return []

    def _save(self):
        """Persist experiences to disk."""
        with open(self.filepath, "w") as f:
            json.dump(self._experiences, f, indent=2, default=str)

    # ── Recording Experiences ───────────────────────────────────────────────

    def record_scan(
        self,
        asset: str,
        rating: int,
        parameter_scores: dict,
        findings_summary: str,
        run_id: str,
    ) -> dict:
        """
        Record a completed scan as an experience.

        Args:
            asset: Asset identifier
            rating: Final 1–10 rating
            parameter_scores: Dict of {param: score}
            findings_summary: Brief text summary of findings
            run_id: Unique scan run ID

        Returns:
            The recorded experience dict.
        """
        experience = {
            "id": f"{self.agent_name}_{int(time.time())}_{asset}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "run_id": run_id,
            "asset": asset,
            "rating": rating,
            "parameter_scores": parameter_scores,
            "findings_summary": findings_summary,
            "feedback": None,           # to be filled by human/orchestrator
            "feedback_applied": False,
        }
        self._experiences.append(experience)
        self._save()
        return experience

    def add_feedback(
        self,
        experience_id: str,
        correct_rating: int | None = None,
        notes: str = "",
        score_adjustments: dict | None = None,
    ):
        """
        Attach human/orchestrator feedback to a past experience.

        This feedback is used on future runs to adjust the agent's
        scoring behavior — creating the RL improvement signal.

        Args:
            experience_id: ID of the experience to annotate
            correct_rating: What the rating should have been (if wrong)
            notes: Free-text feedback for the agent
            score_adjustments: Dict of {param: adjusted_score}
        """
        for exp in self._experiences:
            if exp["id"] == experience_id:
                exp["feedback"] = {
                    "correct_rating": correct_rating,
                    "notes": notes,
                    "score_adjustments": score_adjustments or {},
                    "feedback_time": datetime.now(timezone.utc).isoformat(),
                }
                exp["feedback_applied"] = False
                self._save()
                return
        raise ValueError(f"Experience '{experience_id}' not found")

    # ── Querying for Agent Context ──────────────────────────────────────────

    def get_recent_experiences(self, limit: int = 10) -> list[dict]:
        """Get the most recent N experiences for agent context."""
        return self._experiences[-limit:]

    def get_experiences_for_asset(self, asset: str) -> list[dict]:
        """Get all past experiences for a specific asset."""
        return [e for e in self._experiences if e["asset"] == asset]

    def get_feedback_experiences(self) -> list[dict]:
        """Get experiences that have feedback attached (for learning)."""
        return [e for e in self._experiences if e["feedback"] is not None]

    def get_unapplied_feedback(self) -> list[dict]:
        """Get experiences with feedback that hasn't been incorporated yet."""
        return [
            e for e in self._experiences
            if e["feedback"] is not None and not e["feedback_applied"]
        ]

    def mark_feedback_applied(self, experience_id: str):
        """Mark feedback as applied after the agent has used it."""
        for exp in self._experiences:
            if exp["id"] == experience_id:
                exp["feedback_applied"] = True
                self._save()
                return

    def build_learning_context(self, current_asset: str | None = None) -> str:
        """
        Build a context string to inject into the agent's system prompt.

        This is the core RL mechanism — past experiences and feedback
        become part of the agent's reasoning context, allowing it to
        improve its analysis on each run without fine-tuning.

        Args:
            current_asset: If provided, prioritize history for this asset.

        Returns:
            Formatted string with past experiences and feedback for the agent.
        """
        sections = []

        # 1. Recent scan history
        recent = self.get_recent_experiences(limit=5)
        if recent:
            sections.append("## Recent Scan History")
            for exp in recent:
                line = (
                    f"- Asset: {exp['asset']} | Rating: {exp['rating']}/10 | "
                    f"Summary: {exp['findings_summary']}"
                )
                if exp.get("feedback"):
                    fb = exp["feedback"]
                    if fb.get("correct_rating"):
                        line += f"\n  FEEDBACK: Rating should have been {fb['correct_rating']}/10."
                    if fb.get("notes"):
                        line += f"\n  NOTES: {fb['notes']}"
                sections.append(line)

        # 2. Asset-specific history
        if current_asset:
            asset_history = self.get_experiences_for_asset(current_asset)
            if asset_history:
                sections.append(f"\n## History for {current_asset}")
                for exp in asset_history[-3:]:
                    sections.append(
                        f"- Run {exp['run_id'][:8]} ({exp['timestamp'][:10]}): "
                        f"Rating {exp['rating']}/10"
                    )

        # 3. Feedback patterns (learning signal)
        feedback_exps = self.get_feedback_experiences()
        if feedback_exps:
            sections.append("\n## Learned Patterns (from feedback)")
            for exp in feedback_exps[-5:]:
                fb = exp["feedback"]
                original = exp["rating"]
                corrected = fb.get("correct_rating", original)
                if corrected != original:
                    sections.append(
                        f"- {exp['asset']}: Adjusted {original}/10 → {corrected}/10. "
                        f"Reason: {fb.get('notes', 'no notes')}"
                    )

        if not sections:
            return ""

        return (
            "=== LEARNING CONTEXT (from past scans) ===\n"
            "Use this history to refine your analysis. If feedback indicates\n"
            "your previous ratings were too high or too low, adjust accordingly.\n\n"
            + "\n".join(sections)
            + "\n=== END LEARNING CONTEXT ===\n"
        )

    # ── Stats ───────────────────────────────────────────────────────────────

    @property
    def total_experiences(self) -> int:
        return len(self._experiences)

    @property
    def total_with_feedback(self) -> int:
        return len(self.get_feedback_experiences())

    def summary(self) -> str:
        """Quick stats for logging."""
        return (
            f"LearningStore[{self.agent_name}]: "
            f"{self.total_experiences} experiences, "
            f"{self.total_with_feedback} with feedback"
        )

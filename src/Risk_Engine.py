"""Compute final per-session risk scores from behavior and confidence.
 
This module is part of the TraceGuard behavioral security analytics
pipeline. It is the final stage: it consumes behavior analysis results
(behavior score/label/detected patterns) and confidence results
(identity attribution confidence), blends them into a single risk
score per session, classifies that score into a risk level, and writes
the sorted results as the pipeline's final output.
 
The output schema (risk result dictionary structure and field names)
is relied upon by downstream consumers (e.g. the thesis-defense
dashboard) and must remain unchanged.
"""
 
import json
from pathlib import Path
from typing import Any
 
# ==================================================
# Paths
# ==================================================
 
from config import (
    BEHAVIOR_ANALYSIS_PATH,
    CONFIDENCE_RESULTS_PATH,
    RISK_SCORES_PATH,
)
 
 
def load_json(path: Path) -> Any:
    """Load and parse a JSON file.
 
    Args:
        path: Path to the JSON file to read.
 
    Returns:
        The parsed JSON content.
    """
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)
 
 
def save_json(path: Path, data: Any) -> None:
    """Serialize data to a JSON file.
 
    Args:
        path: Destination path for the JSON output file.
        data: The JSON-serializable data to write.
    """
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
 
 
def classify_risk(score: float) -> str:
    """Classify a risk score into a risk level label.
 
    Args:
        score: The session's final risk score.
 
    Returns:
        `"HIGH"` if `score >= 0.6`, `"MEDIUM"` if `score >= 0.3`,
        otherwise `"LOW"`.
    """
    if score >= 0.6:
        return "HIGH"
    if score >= 0.3:
        return "MEDIUM"
    return "LOW"
 
 
def compute_risk(
    behavior_results: list[dict[str, Any]],
    confidence_results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Blend behavior and confidence results into a final risk score per session.
 
    Args:
        behavior_results: Per-session behavior analysis results, each
            with `session_id`, `user`, `behavior_score`,
            `behavior_label`, and `patterns_detected`.
        confidence_results: Per-session confidence results, each with
            `session_id` and `confidence_score`.
 
    Returns:
        A list of risk result dictionaries, one per input behavior
        result, sorted by `risk_score` in descending order.
    """
    conf_map = {result["session_id"]: result for result in confidence_results}
    output = []
 
    for behavior_result in behavior_results:
        sid = behavior_result["session_id"]
        confidence_result = conf_map.get(sid, {})
 
        behavior = behavior_result["behavior_score"]
        confidence = confidence_result.get("confidence_score", 0.0)
 
        if confidence <= 0.0:
            # No confidence data for this session (e.g. it wasn't
            # matched during correlation) — fall back to the raw
            # behavior score rather than diluting it with a missing
            # confidence weight.
            risk_score = round(behavior, 4)
        else:
            # risk = 0.7 × behavior + 0.3 × confidence
            # Behavior is the primary security signal (what the session
            # actually did), so it carries the larger weight. Confidence
            # is a secondary adjustment reflecting how reliable the
            # session's user attribution is — a behaviorally risky
            # session attributed with low confidence should be weighted
            # down slightly relative to one attributed with certainty.
            risk_score = round((behavior * 0.7) + (confidence * 0.3), 4)
 
        output.append({
            "session_id": sid,
            "user": behavior_result["user"],
            "behavior_score": behavior_result["behavior_score"],
            "behavior_label": behavior_result["behavior_label"],
            "patterns_detected": behavior_result["patterns_detected"],
            "confidence_score": confidence,
            "risk_score": risk_score,
            "risk_level": classify_risk(risk_score)
        })
 
    output.sort(key=lambda result: result["risk_score"], reverse=True)
    return output
 
 
def main() -> None:
    """Run the risk-scoring stage of the TraceGuard pipeline.
 
    Loads behavior and confidence results, computes the final blended
    risk score for every session, writes the sorted results, and prints
    a per-session summary to stdout.
    """
    behavior = load_json(BEHAVIOR_ANALYSIS_PATH)
    confidence = load_json(CONFIDENCE_RESULTS_PATH)
    risks = compute_risk(behavior, confidence)
    save_json(RISK_SCORES_PATH, risks)
 
    print("Risk engine complete.")
    for risk_result in risks:
        print(f"  [{risk_result['risk_level']:6s}] session={risk_result['session_id']}"
              f"  user={risk_result['user']}"
              f"  risk={risk_result['risk_score']:.4f}")
 
 
if __name__ == "__main__":
    main()
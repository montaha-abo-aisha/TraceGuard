"""Compute per-session identity confidence scores.
 
This module is part of the TraceGuard behavioral security analytics
pipeline. It consumes sessions (from the sessionization stage) and
session graphs (from the graph-building stage), and computes a
multiplicative confidence score per session from five independent
factors: timing (how close correlated events are to their matched
audit event), sequence (how tightly spaced the session's events are),
continuity (how large the largest gap is), ambiguity (how uncertain
user attribution is per event), and process relationship (how
concentrated vs. diffuse the session's process interaction graph is).
The output feeds the downstream risk-scoring stage.
 
The output schema (confidence result dictionary structure and field
names) is relied upon by other TraceGuard pipeline modules and must
remain unchanged.
"""
 
from __future__ import annotations
 
import json
import math
from pathlib import Path
from typing import Any
 
import numpy as np
 
# ==================================================
# Paths
# ==================================================
 
from config import (
    SESSIONS_PATH,
    SESSION_GRAPHS_PATH,
    CONFIDENCE_RESULTS_PATH,
)
 
# Tau — time constants derived from empirical data
tau_t = 20.08
tau_s = 146.8
tau_c = 160.0
 
 
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
 
 
# ----------------------------
# 1) Timing Score
# timing_score = exp(-Δt / τ_t)
# ----------------------------
def calculate_timing_score(delta_t: float, tau_t: float) -> float:
    """Score how close a matched audit event's timing is to its Falco alert.
 
    Args:
        delta_t: The time difference (in seconds) between the audit
            event and the Falco alert it was matched to.
        tau_t: The timing decay constant.
 
    Returns:
        The exponential timing score, `exp(-delta_t / tau_t)`.
    """
    return math.exp(-delta_t / tau_t)
 
 
# ----------------------------
# 2) Sequence Score
# sequence = exp(- (α * avg_gap + β * max_gap) / τ_s)
# ----------------------------
def calculate_sequence_score(
    events: list[dict[str, Any]], tau_s: float, alpha: float = 0.5, beta: float = 0.5
) -> tuple[float, float, float]:
    """Score how tightly spaced a session's events are.
 
    Args:
        events: The session's ordered events.
        tau_s: The sequence decay constant.
        alpha: Weight applied to the average inter-event gap.
        beta: Weight applied to the maximum inter-event gap.
 
    Returns:
        A tuple of `(sequence_score, avg_gap, max_gap)`. If fewer than
        two events are present, returns `(1.0, 0.0, 0.0)`.
    """
    timestamps = sorted([event["timestamp"] for event in events])
 
    if len(timestamps) < 2:
        return 1.0, 0.0, 0.0
 
    gaps = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
    avg_gap = float(np.mean(gaps))
    max_gap = float(max(gaps))
 
    score = math.exp(-((alpha * avg_gap) + (beta * max_gap)) / tau_s)
    return score, avg_gap, max_gap
 
 
# ----------------------------
# 3) Continuity Score
# continuity = exp(- max_gap / τ_c)
# ----------------------------
def calculate_continuity_score(max_gap: float, tau_c: float) -> float:
    """Score session continuity based on its largest inter-event gap.
 
    Args:
        max_gap: The largest gap (in seconds) between consecutive
            events in the session.
        tau_c: The continuity decay constant.
 
    Returns:
        The exponential continuity score, `exp(-max_gap / tau_c)`.
    """
    return math.exp(-max_gap / tau_c)
 
 
# ----------------------------
# 4) Ambiguity Score
# Computed per event over its candidates, not over the whole session
# ----------------------------
def calculate_ambiguity_score(timing_scores: list[float]) -> float:
    """Score how ambiguous user attribution is for a single event.
 
    Args:
        timing_scores: The timing scores of every candidate user for
            one event.
 
    Returns:
        1.0 if there is exactly one candidate (certain, no ambiguity);
        otherwise a score in [0.0, 1.0] derived from the top candidate's
        share of total score and its margin over the second candidate.
        Returns 0.0 if `timing_scores` is empty or sums to zero.
    """
    if not timing_scores:
        return 0.0
 
    # A single candidate is certain — no ambiguity.
    if len(timing_scores) == 1:
        return 1.0
 
    sorted_scores = sorted(timing_scores, reverse=True)
    max_score = sorted_scores[0]
    second_max = sorted_scores[1]
 
    total = sum(timing_scores)
    if total == 0:
        return 0.0
 
    ratio = max_score / total
    margin = max_score - second_max
 
    return min(1.0, ratio * (1.0 + margin))
 
 
# ----------------------------
# 5) Process Relationship Score
# ----------------------------
def calculate_process_relationship_score(
    session: dict[str, Any], graph_map: dict[str, Any]
) -> float:
    """Score a session based on the concentration of its process interaction graph.
 
    Combines the average edge weight in the session's graph with an
    entropy term over each node's in-weight distribution: a session
    dominated by a few strong, concentrated process relationships
    scores higher than one with diffuse, evenly spread interactions.
 
    Args:
        session: The session dictionary (used only for `session_id`).
        graph_map: Mapping from `session_id` to that session's graph
            (nodes and edges), as built by the graph-building stage.
 
    Returns:
        A process relationship score in [0.0, 1.0]. Returns 0.0 if the
        session's graph has one or zero nodes, or no positive in-weight
        edges.
    """
    graph = graph_map.get(session["session_id"], {"nodes": [], "edges": []})
 
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])
 
    node_count = len(nodes)
    if node_count <= 1:
        return 0.0
 
    total_weight = sum(edge.get("weight", 0.0) for edge in edges)
 
    # Fix: divide by the actual number of edges, not node_count - 1.
    avg_weight = total_weight / len(edges) if edges else 0.0
 
    # Fix: compute entropy over node in-weights, not over raw edges.
    in_weights = {}
    for edge in edges:
        target = edge["target"]
        in_weights[target] = in_weights.get(target, 0) + edge.get("weight", 0.0)
 
    weights = [weight for weight in in_weights.values() if weight > 0]
 
    if not weights:
        return 0.0
 
    weight_sum = sum(weights)
    probs = [weight / weight_sum for weight in weights]
 
    entropy = -sum(prob * math.log(prob) for prob in probs if prob > 0)
    max_entropy = math.log(len(probs)) if len(probs) > 1 else 1.0
    normalized_entropy = entropy / max_entropy if max_entropy > 0 else 0.0
 
    score = avg_weight * (1 - normalized_entropy)
 
    # Clamp so the score never exceeds 1.0.
    return min(score, 1.0)
 
 
def main() -> None:
    """Run confidence scoring over all sessions and write the results.
 
    Loads sessions and session graphs, computes the five-factor
    confidence score for every session, writes the full results to
    `CONFIDENCE_RESULTS_PATH`, and prints a small sample to stdout.
    """
    sessions = load_json(SESSIONS_PATH)
    graphs = load_json(SESSION_GRAPHS_PATH)
 
    graph_map = {graph["session_id"]: graph for graph in graphs}
 
    confidence_results = []
 
    for session in sessions:
        events = session["ordered_events"]
 
        # ---- Timing score
        primary_timing_scores = []
 
        for event in events:
            candidates = event.get("candidate_users", [])
            if candidates:
                candidate_scores = [
                    calculate_timing_score(candidate["time_diff"], tau_t)
                    for candidate in candidates
                ]
                primary_timing_scores.append(max(candidate_scores))
 
        timing_score = float(np.mean(primary_timing_scores)) if primary_timing_scores else 0.0
 
        # ---- Sequence
        sequence_score, avg_gap, max_gap = calculate_sequence_score(events, tau_s)
 
        # ---- Continuity
        continuity_score = calculate_continuity_score(max_gap, tau_c)
 
        # ---- Ambiguity: computed per event over its candidates
        per_event_ambiguities = []
        for event in events:
            candidates = event.get("candidate_users", [])
            if candidates:
                scores = [
                    calculate_timing_score(candidate["time_diff"], tau_t)
                    for candidate in candidates
                ]
                per_event_ambiguities.append(calculate_ambiguity_score(scores))
 
        ambiguity_score = float(np.mean(per_event_ambiguities)) if per_event_ambiguities else 1.0
 
        # ---- Process Relationship
        process_relationship_score = calculate_process_relationship_score(session, graph_map)
 
        # ---- Final confidence
        confidence_score = (
            timing_score *
            sequence_score *
            continuity_score *
            ambiguity_score *
            process_relationship_score
        )
 
        confidence_results.append({
            "session_id": session["session_id"],
            "user": session["user"],
            "pod": session["pod"],
            "namespace": session["namespace"],
 
            "timing_score": round(timing_score, 4),
            "sequence_score": round(sequence_score, 4),
            "continuity_score": round(continuity_score, 4),
            "ambiguity_score": round(ambiguity_score, 4),
            "process_relationship_score": round(process_relationship_score, 4),
 
            "avg_gap": round(avg_gap, 4),
            "max_gap": round(max_gap, 4),
 
            "confidence_score": round(confidence_score, 4)
        })
 
    save_json(CONFIDENCE_RESULTS_PATH, confidence_results)
 
    print("Confidence Results Sample:")
    print(json.dumps(confidence_results[:3], indent=2, ensure_ascii=False))
 
 
if __name__ == "__main__":
    main()
"""Correlate Falco runtime alerts with normalized auditd events.

This module is part of the TraceGuard behavioral security analytics
pipeline. For each Falco alert it searches nearby auditd events (same
pod/namespace, occurring at or before the alert) within an adaptive,
rule-type-specific time window, scores candidate matches by temporal
proximity, and attaches the most likely originating user/process to the
alert. The output feeds the downstream sessionization stage.

The output schema (field names and dictionary structure of each
correlated event) is relied upon by other TraceGuard pipeline modules
and must remain unchanged.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# ==================================================
# Constants
# ==================================================

from config import (
    NORMALIZED_FALCO_PATH as FALCO_EVENTS_PATH,
    NORMALIZED_AUDIT_PATH as AUDIT_EVENTS_PATH,
    CORRELATED_EVENTS_PATH,
)

JSON_INDENT = 2
SCORE_PRECISION = 3

# Adaptive per-rule-type time windows (in seconds), tried in order from
# the tightest to the widest until at least one candidate is found.
#
# NOTE: This module-level constant is not referenced internally (the
# per-rule-type windows below are defined directly in `get_time_window`
# to keep each rule category self-contained and independently tunable).
# It is preserved as-is, unrenamed, in case it is imported by another
# module in the pipeline.
WINDOWS = [2, 5, 10]

SHELL_EXEC_WINDOWS = [2, 5, 10]
NETWORK_WINDOWS = [5, 10, 20]
DEFAULT_WINDOWS = [5, 10, 15]

# Match classification thresholds applied to the temporal-proximity score.
STRONG_MATCH_THRESHOLD = 0.8
WEAK_MATCH_THRESHOLD = 0.4

STRONG_MATCH = "strong_match"
WEAK_MATCH = "weak_match"
NO_MATCH = "no_match"
COLLISION_MATCH = "collision"

UNKNOWN_USER_ID = "unknown"
UNKNOWN_USERNAME = "unknown"
NOT_AVAILABLE = "N/A"


# ==================================================
# Scoring helpers
# ==================================================
def calculate_score(time_diff: float, max_window: float) -> float:
    """Score how closely an audit event's timing matches a Falco alert.

    The score decays linearly from 1.0 (zero time difference) to 0.0 at
    the edge of the window, and is 0.0 for any difference beyond it.

    Args:
        time_diff: Time elapsed (in seconds) between the audit event and
            the Falco alert.
        max_window: The size (in seconds) of the time window being
            evaluated.

    Returns:
        A proximity score in the range [0.0, 1.0], rounded to
        `SCORE_PRECISION` decimal places.
    """
    if time_diff > max_window:
        return 0.0
    return round(1 - (time_diff / max_window), SCORE_PRECISION)


def classify_match(score: float) -> str:
    """Classify a proximity score into a match-strength label.

    Args:
        score: A proximity score as returned by `calculate_score`.

    Returns:
        One of `STRONG_MATCH`, `WEAK_MATCH`, or `NO_MATCH`.
    """
    if score >= STRONG_MATCH_THRESHOLD:
        return STRONG_MATCH
    if score >= WEAK_MATCH_THRESHOLD:
        return WEAK_MATCH
    return NO_MATCH


# ==================================================
# I/O helpers
# ==================================================
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
        json.dump(data, f, indent=JSON_INDENT, ensure_ascii=False)


# ==================================================
# Correlation
# ==================================================
def get_time_window(rule: str) -> list[int]:
    """Select the candidate time windows for a given Falco rule type.

    Args:
        rule: The Falco rule name/description associated with an alert.

    Returns:
        A list of candidate window sizes (in seconds), ordered from
        tightest to widest, to try when searching for correlated audit
        events.
    """
    rule = rule.lower()
    if "shell" in rule or "exec" in rule:
        return SHELL_EXEC_WINDOWS
    if "network" in rule or "connect" in rule:
        return NETWORK_WINDOWS
    return DEFAULT_WINDOWS


def find_candidates(
    falco_event: dict[str, Any],
    audit_events: list[dict[str, Any]],
    window: int,
) -> list[dict[str, Any]]:
    """Find candidate audit events that could explain a Falco alert.

    An audit event is a candidate if it occurred in the same pod and
    namespace as the alert, at or before the alert's timestamp, and
    within `window` seconds of it. When multiple audit events belong to
    the same user, only that user's best-scoring candidate is kept.

    Args:
        falco_event: A normalized Falco alert event.
        audit_events: The full list of normalized auditd events to
            search.
        window: The time window (in seconds) to search within.

    Returns:
        A list of unique best-match candidates, one per distinct user
        that had a qualifying audit event.
    """
    raw_candidates = []

    for audit_event in audit_events:
        same_pod = falco_event["pod"] == audit_event["pod"]
        same_namespace = falco_event["namespace"] == audit_event["namespace"]

        if not same_pod or not same_namespace:
            continue

        time_diff = falco_event["timestamp"] - audit_event["timestamp"]

        if time_diff < 0:
            continue

        if time_diff <= window:
            score = calculate_score(time_diff, window)

            raw_candidates.append({
                "user": audit_event["user_id"],
                "username": audit_event["user"],
                "time_diff": time_diff,
                "score": score,
            })

    # Deduplicate candidates, keeping the best match per user: the
    # highest score, and on a tie, the smallest time difference.
    unique_candidates: dict[Any, dict[str, Any]] = {}

    for candidate in raw_candidates:
        user_id = candidate["user"]
        best_so_far = unique_candidates.get(user_id)

        if best_so_far is None:
            unique_candidates[user_id] = candidate
        elif candidate["score"] > best_so_far["score"]:
            unique_candidates[user_id] = candidate
        elif (
            candidate["score"] == best_so_far["score"]
            and candidate["time_diff"] < best_so_far["time_diff"]
        ):
            unique_candidates[user_id] = candidate

    return list(unique_candidates.values())


def _build_unresolved_event(
    falco_event: dict[str, Any],
    match: str,
    window_used: int | None,
    candidate_users: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build a correlated-event dict for the no-match/collision cases.

    Factored out of `correlate` because the "no_match" and "collision"
    branches previously built an identical dictionary shape, differing
    only in the `match` label, `window_used`, and `candidate_users`
    values. This does not change the resulting output structure.

    Args:
        falco_event: The Falco alert being processed.
        match: The match classification to record (`NO_MATCH` or
            `COLLISION_MATCH`).
        window_used: The time window that was in effect, or ``None`` if
            no window produced a candidate.
        candidate_users: The candidate list to attach (empty for
            `NO_MATCH`, the tied top candidates for `COLLISION_MATCH`).

    Returns:
        A correlated-event dictionary with no primary match assigned.
    """
    return {
        "action": falco_event["rule"],
        "timestamp": falco_event["timestamp"],
        "pod": falco_event["pod"],
        "namespace": falco_event["namespace"],
        "user": UNKNOWN_USER_ID,
        "username": UNKNOWN_USERNAME,
        "proc_cmdline": falco_event.get("proc_cmdline", NOT_AVAILABLE),
        "file": falco_event.get("fd_name", NOT_AVAILABLE),
        "match": match,
        "window_used": window_used,
        "primary_match": None,
        "candidate_users": candidate_users,
    }


def correlate(
    falco_events: list[dict[str, Any]],
    audit_events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Correlate each Falco alert with its most likely originating user.

    For every Falco alert, progressively widening time windows (as
    determined by `get_time_window`) are searched for candidate audit
    events until a match is found. The best-scoring candidate is
    attached to the alert; ties between top candidates are reported as
    a "collision" rather than an arbitrary pick.

    Args:
        falco_events: Normalized Falco alert events.
        audit_events: Normalized auditd events to correlate against.

    Returns:
        A list of correlated event dictionaries, one per input Falco
        alert, annotated with the matched user (if any) and match
        metadata.
    """
    correlated = []

    for falco_event in falco_events:
        windows = get_time_window(falco_event["rule"])
        candidates: list[dict[str, Any]] = []
        window_used = None

        for window in windows:
            candidates = find_candidates(falco_event, audit_events, window)
            if candidates:
                window_used = window
                break

        if not candidates:
            correlated.append(
                _build_unresolved_event(falco_event, NO_MATCH, None, [])
            )
            continue

        candidates.sort(key=lambda c: (-c["score"], c["time_diff"]))

        best_score = candidates[0]["score"]
        top_candidates = [c for c in candidates if c["score"] == best_score]

        # Timestamp collision: multiple users tie for the best score, so
        # no single primary match can be confidently attributed.
        if len(top_candidates) > 1:
            correlated.append(
                _build_unresolved_event(
                    falco_event, COLLISION_MATCH, window_used, top_candidates
                )
            )
            continue

        primary = candidates[0]

        correlated.append({
            "action": falco_event["rule"],
            "timestamp": falco_event["timestamp"],
            "pod": falco_event["pod"],
            "namespace": falco_event["namespace"],
            "user_id": primary["user"],
            "user": primary["username"],
            "proc_cmdline": falco_event.get("proc_cmdline", NOT_AVAILABLE),
            "file": falco_event.get("fd_name", NOT_AVAILABLE),
            "match": classify_match(primary["score"]),
            "window_used": window_used,
            "primary_match": primary,
            "candidate_users": candidates,
        })

    return correlated


# ==================================================
# Main
# ==================================================
def main() -> None:
    """Run the correlation stage of the TraceGuard event pipeline.

    Loads normalized Falco and auditd events, correlates each alert with
    its most likely originating user, writes the result to the
    pipeline's expected output location, and prints a summary.
    """
    falco_events = load_json(FALCO_EVENTS_PATH)
    audit_events = load_json(AUDIT_EVENTS_PATH)
    result = correlate(falco_events, audit_events)
    save_json(CORRELATED_EVENTS_PATH, result)

    print(f"Correlation complete — {len(result)} events")
    print()
    for event in result:
        print(f"  action    : {event['action']}")
        print(f"  user      : {event['user']}")
        print(f"  match     : {event['match']}")
        print(f"  window    : {event['window_used']}s")
        print(f"  candidates: {[c['username'] for c in event['candidate_users']]}")
        print()


if __name__ == "__main__":
    main()
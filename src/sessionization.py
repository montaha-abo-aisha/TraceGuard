"""Group correlated security events into user/pod/namespace sessions.

This module is part of the TraceGuard behavioral security analytics
pipeline. It consumes normalized auditd events and correlated Falco
events, groups them by identity (user, pod, namespace), and splits each
identity's event stream into discrete sessions based on an inactivity
threshold (a gap between consecutive events large enough to be treated
as a session boundary). The output feeds the downstream graph-building
stage.

The output schema (session dictionary structure and field names) is
relied upon by other TraceGuard pipeline modules and must remain
unchanged.
"""

from __future__ import annotations

import json
import math
from collections import defaultdict
from pathlib import Path
from typing import Any

# ==================================================
# Constants
# ==================================================

from config import (
    NORMALIZED_AUDIT_PATH as AUDIT_EVENTS_PATH,
    CORRELATED_EVENTS_PATH,
    SESSIONS_PATH,
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


def percentile(values: list[float], p: float) -> float:
    """Compute the p-th percentile of a list of values via interpolation.

    Uses linear interpolation between the two nearest ranks, matching the
    conventional "linear" percentile method.

    Args:
        values: The numeric values to compute a percentile over. Does
            not need to be pre-sorted.
        p: The percentile to compute, in the range [0, 100].

    Returns:
        The interpolated percentile value, or ``0`` if `values` is
        empty.
    """
    if not values:
        return 0

    values = sorted(values)
    if len(values) == 1:
        return float(values[0])

    rank = (len(values) - 1) * (p / 100.0)
    lower_index = math.floor(rank)
    upper_index = math.ceil(rank)

    if lower_index == upper_index:
        return float(values[int(rank)])

    lower_weighted = values[lower_index] * (upper_index - rank)
    upper_weighted = values[upper_index] * (rank - lower_index)
    return float(lower_weighted + upper_weighted)


def is_valid_event(event: Any) -> bool:
    """Check whether an event has the minimum fields needed for sessionization.

    Args:
        event: A candidate event, expected to be a dictionary.

    Returns:
        ``True`` if `event` is a dict containing non-empty `user`,
        `pod`, `namespace`, and an integer-convertible `timestamp`;
        ``False`` otherwise.
    """
    required_fields = ["user", "pod", "namespace", "timestamp"]

    if not isinstance(event, dict):
        return False

    for field in required_fields:
        if field not in event:
            return False
        if event[field] in [None, ""]:
            return False

    try:
        int(event["timestamp"])
    except (ValueError, TypeError):
        return False

    return True


def _group_events_by_identity(
    events: list[dict[str, Any]]
) -> defaultdict[tuple[Any, Any, Any], list[dict[str, Any]]]:
    """Group valid events by their (user, pod, namespace) identity.

    Factored out because both `estimate_inactivity_threshold` and
    `sessionize` previously repeated this identical filter-and-group
    step. Grouping key and validity filtering are unchanged from the
    original inline logic in either function.

    Args:
        events: Candidate events to filter and group. Invalid events
            (per `is_valid_event`) are silently skipped, matching the
            original behavior.

    Returns:
        A mapping from `(user, pod, namespace)` identity tuples to the
        list of valid events sharing that identity, in original order.
    """
    grouped: defaultdict[tuple[Any, Any, Any], list[dict[str, Any]]] = defaultdict(list)

    for event in events:
        if not is_valid_event(event):
            continue

        key = (event["user"], event["pod"], event["namespace"])
        grouped[key].append(event)

    return grouped


def estimate_inactivity_threshold(
    events: list[dict[str, Any]], fallback: int = 120
) -> int:
    """Estimate the inactivity gap (in seconds) that defines a session boundary.

    Gaps between consecutive events (per user/pod/namespace identity)
    are collected, and the threshold is derived from them.

    Args:
        events: Events to analyze for inter-event gaps.
        fallback: The threshold to return if no gaps could be computed
            (e.g., no identity has more than one valid event).

    Returns:
        The inactivity threshold in seconds, at least 1.
    """
    grouped = _group_events_by_identity(events)

    gaps = []

    for events in grouped.values():
        timestamps = sorted(int(event["timestamp"]) for event in events)
        for i in range(1, len(timestamps)):
            gap = timestamps[i] - timestamps[i - 1]
            if gap > 0:
                gaps.append(gap)

    if not gaps:
        return fallback

    # NOTE: A percentile-based adaptive threshold (60th percentile of
    # observed inter-event gaps) was previously used here but is
    # currently disabled in favor of a fixed threshold. Left in place
    # intentionally as a documented design decision / potential future
    # option; do not remove `percentile()` or re-enable without review.
    # threshold = int(round(percentile(gaps, 60)))
    # return max(threshold, 1)
    threshold = 120
    return max(threshold, 1)


def build_session(
    session_id: str, key: tuple[Any, Any, Any], events: list[dict[str, Any]]
) -> dict[str, Any]:
    """Build a session dictionary from a contiguous run of events.

    Args:
        session_id: Unique identifier to assign to this session.
        key: The `(user, pod, namespace)` identity tuple for this
            session.
        events: The ordered events belonging to this session.

    Returns:
        A session dictionary with identity, time bounds, and the
        ordered events it contains.
    """
    timestamps = [int(event["timestamp"]) for event in events]

    return {
        "session_id": session_id,
        "user": key[0],
        "pod": key[1],
        "namespace": key[2],
        "start_time": min(timestamps),
        "end_time": max(timestamps),
        "ordered_events": events,
    }


def sessionize(
    correlated_events: list[dict[str, Any]], inactivity_threshold: int
) -> list[dict[str, Any]]:
    """Split events into sessions based on an inactivity threshold.

    Events are grouped by `(user, pod, namespace)` identity, sorted by
    timestamp, and split into a new session whenever the gap between
    consecutive events exceeds `inactivity_threshold`.

    Args:
        correlated_events: Events to sessionize.
        inactivity_threshold: The maximum gap (in seconds) allowed
            between consecutive events before starting a new session.

    Returns:
        All resulting sessions, sorted by `start_time`.
    """
    grouped = _group_events_by_identity(correlated_events)

    sessions = []
    session_counter = 1

    for key, events in grouped.items():
        if not events:
            continue

        events.sort(key=lambda event: int(event["timestamp"]))

        current_session_events = [events[0]]

        for event in events[1:]:
            gap = int(event["timestamp"]) - int(current_session_events[-1]["timestamp"])

            if gap > inactivity_threshold:
                sessions.append(
                    build_session(f"session-{session_counter}", key, current_session_events)
                )
                session_counter += 1
                current_session_events = [event]
            else:
                current_session_events.append(event)

        sessions.append(
            build_session(f"session-{session_counter}", key, current_session_events)
        )
        session_counter += 1

    sessions.sort(key=lambda s: s["start_time"])
    return sessions


if __name__ == "__main__":
    audit_events = load_json(AUDIT_EVENTS_PATH)
    correlated_events = load_json(CORRELATED_EVENTS_PATH)

    all_events = audit_events + correlated_events

    threshold = estimate_inactivity_threshold(all_events)
    sessions = sessionize(all_events, threshold)
    save_json(SESSIONS_PATH, sessions)

    print("Sessionization completed successfully.")
    print(f"Inactivity threshold: {threshold} seconds")
    print(f"Sessions created: {len(sessions)}")
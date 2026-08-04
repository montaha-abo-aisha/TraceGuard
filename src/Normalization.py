"""Normalize raw auditd and Falco security events into a unified schema.

This module is part of the TraceGuard behavioral security analytics
pipeline. It reads raw audit and Falco event logs, converts them into a
common normalized record format (shared timestamp representation, field
names, and Kubernetes context), sorts each event stream chronologically,
and writes the normalized output for consumption by downstream pipeline
stages (sessionization, graph building, etc.).

The normalized schema, field names, and output file locations are relied
upon by other TraceGuard pipeline modules and must remain unchanged.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

# ==================================================
# Constants
# ==================================================

from config import (
    RAW_AUDIT_PATH as AUDIT_EVENTS_PATH,
    RAW_FALCO_PATH as FALCO_EVENTS_PATH,
    NORMALIZED_AUDIT_PATH,
    NORMALIZED_FALCO_PATH,
)

JSON_INDENT = 2
DEFAULT_SORT_TIMESTAMP = 0  # Fallback used when an event has no timestamp.

# Errors that can occur while parsing a malformed or missing ISO-8601
# timestamp string. Kept narrow (rather than a bare `except Exception`)
# so that unrelated bugs are not silently swallowed.
TIMESTAMP_PARSE_ERRORS = (ValueError, AttributeError, TypeError)


# ==================================================
# Helpers
# ==================================================
def to_epoch(timestamp: str | None) -> int | None:
    """Convert an ISO-8601 timestamp string to a Unix epoch integer.

    Args:
        timestamp: An ISO-8601 formatted timestamp string, optionally
            using a trailing "Z" to denote UTC. May be ``None``.

    Returns:
        The Unix epoch time as an integer, or ``None`` if ``timestamp``
        is missing or cannot be parsed.
    """
    try:
        return int(datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp())
    except TIMESTAMP_PARSE_ERRORS:
        return None


def extract_k8s(event: dict[str, Any]) -> dict[str, Any]:
    """Extract Kubernetes pod/namespace context from a raw event.

    Args:
        event: A raw auditd or Falco event dictionary.

    Returns:
        A dictionary with ``pod`` and ``namespace`` keys, defaulting to
        ``None`` when the source event has no ``k8s`` context.
    """
    k8s = event.get("k8s", {})
    return {
        "pod": k8s.get("pod"),
        "namespace": k8s.get("namespace"),
    }


# ==================================================
# Normalization
# ==================================================
def normalize_audit_event(event: dict[str, Any]) -> dict[str, Any]:
    """Normalize a raw auditd event into the common event schema.

    Args:
        event: A raw auditd event dictionary.

    Returns:
        A normalized event dictionary conforming to the shared TraceGuard
        event schema.
    """
    k8s = extract_k8s(event)
    user_id = event.get("auid") or event.get("uid") or event.get("user")

    return {
        "timestamp": to_epoch(event.get("timestamp")),
        "source": "auditd",
        "event_type": event.get("event_type"),
        "user": event.get("user"),
        "user_id": user_id,
        "pod": k8s["pod"],
        "namespace": k8s["namespace"],
        "proc_name": event.get("process"),
        "proc_cmdline": event.get("command"),
        "pid": event.get("pid"),
        "ppid": event.get("ppid"),
        "dest_ip": None,
        "dest_port": None,
    }


def normalize_falco_event(event: dict[str, Any]) -> dict[str, Any]:
    """Normalize a raw Falco alert event into the common event schema.

    Args:
        event: A raw Falco event dictionary.

    Returns:
        A normalized event dictionary conforming to the shared TraceGuard
        event schema.
    """
    k8s = extract_k8s(event)
    connection = event.get("connection", {})

    return {
        "timestamp": to_epoch(event.get("timestamp")),
        "source": "falco",
        "event_type": "alert",
        "user": event.get("user"),
        "pod": k8s["pod"],
        "namespace": k8s["namespace"],
        "proc_name": event.get("process"),
        "proc_cmdline": None,
        "pid": None,
        "ppid": None,
        "dest_ip": connection.get("dest_ip"),
        "dest_port": connection.get("dest_port"),
        "rule": event.get("rule"),
        "priority": event.get("priority"),
    }


# ==================================================
# I/O helpers
# ==================================================
def load_events(path: Path) -> list[dict[str, Any]]:
    """Load a JSON array of raw event dictionaries from disk.

    Args:
        path: Path to a JSON file containing a list of event objects.

    Returns:
        The parsed list of raw event dictionaries.
    """
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def save_events(events: list[dict[str, Any]], path: Path) -> None:
    """Write a list of normalized event dictionaries to disk as JSON.

    Args:
        events: The normalized events to serialize.
        path: Destination path for the JSON output file.
    """
    with path.open("w", encoding="utf-8") as f:
        json.dump(events, f, indent=JSON_INDENT)


# ==================================================
# Main
# ==================================================
def main() -> None:
    """Run the normalization stage of the TraceGuard event pipeline.

    Loads raw auditd and Falco events, normalizes each into the shared
    event schema, sorts them chronologically, and writes the results to
    the pipeline's expected output locations.
    """
    audit_events = load_events(AUDIT_EVENTS_PATH)
    falco_events = load_events(FALCO_EVENTS_PATH)

    # Normalize separately.
    normalized_audit = [normalize_audit_event(e) for e in audit_events]
    normalized_falco = [normalize_falco_event(e) for e in falco_events]

    # Sort each stream chronologically; events with no timestamp sort first.
    normalized_audit.sort(key=lambda e: e["timestamp"] or DEFAULT_SORT_TIMESTAMP)
    normalized_falco.sort(key=lambda e: e["timestamp"] or DEFAULT_SORT_TIMESTAMP)

    # Save separately.
    save_events(normalized_audit, NORMALIZED_AUDIT_PATH)
    save_events(normalized_falco, NORMALIZED_FALCO_PATH)

    print("Normalization complete.")
    print(f"Audit events: {len(normalized_audit)}")
    print(f"Falco events: {len(normalized_falco)}")


if __name__ == "__main__":
    main()
"""Extract behavioral features and score session risk patterns.

This module is part of the TraceGuard behavioral security analytics
pipeline. It consumes sessions (as produced by the sessionization
stage), extracts a fixed set of binary/normalized behavioral features
per session from process commands and Falco actions, scores a set of
named attack-pattern categories (reverse shell, download & execute,
reconnaissance, privilege escalation, lateral movement, data
exfiltration, persistence, container escape), and aggregates those
pattern scores into an overall behavior score and label. The output
feeds the downstream risk-scoring stage.

The output schema (behavior score/label, pattern scores, and detected
pattern list) is relied upon by other TraceGuard pipeline modules and
must remain unchanged.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

# ==================================================
# Paths
# ==================================================

from config import (
    SESSIONS_PATH,
    BEHAVIOR_ANALYSIS_PATH,
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


# ==================================================
# Configuration
# ==================================================

SUSPICIOUS_SHELLS = ["bash", "sh", "zsh", "dash"]

NETWORK_TOOLS = [
    "nc",
    "netcat",
    "ncat",
    "socat"
]
DOWNLOAD_TOOLS = ["curl", "wget"]

EXEC_KEYWORDS = [
    "chmod +x",
    "./",
    "sh ",
    "bash ",
    "python ",
    "perl ",
    "ruby "
]

# ==================================================
# Helpers
# ==================================================

def safe_cmd(event: dict[str, Any]) -> str:
    """Extract a lowercased command line from an event, regardless of schema.

    Supports flat, nested, and ordered_events schemas.

    Args:
        event: A single event dictionary, in any of the supported
            schema shapes.

    Returns:
        The lowercased command line if one can be found, otherwise an
        empty string.
    """

    if "proc_cmdline" in event:
        return str(event.get("proc_cmdline", "") or "").lower()

    if "event" in event:
        return str(
            event.get("event", {})
                 .get("process_info", {})
                 .get("proc_cmdline", "")
        ).lower()

    if "ordered_events" in event:
        for sub_event in event["ordered_events"]:
            cmd = sub_event.get("proc_cmdline")
            if cmd:
                return str(cmd).lower()

    return ""


def safe_action(event: dict[str, Any]) -> str:
    """Read the 'action' field from an event (lowercased).

    Args:
        event: A single event dictionary.

    Returns:
        The lowercased `action` field, or an empty string if absent.
    """
    return str(event.get("action", "") or "").lower()


def normalize_count(count: float, threshold: float) -> float:
    """Normalize a count to the range [0.0, 1.0] relative to a threshold.

    Args:
        count: The raw count to normalize.
        threshold: The count at which the normalized value reaches 1.0.

    Returns:
        `count / threshold`, capped at 1.0.
    """
    return min(count / threshold, 1.0)


def binary_feature(condition: bool) -> float:
    """Convert a boolean condition into a 0.0/1.0 feature value.

    Args:
        condition: The condition to convert.

    Returns:
        1.0 if `condition` is truthy, otherwise 0.0.
    """
    return 1.0 if condition else 0.0


def aggregate_scores(scores: Iterable[float]) -> float:
    """Combine multiple independent scores into a single probability-like score.

    Uses a noisy-OR style combination: the result is 1 minus the
    product of each score's complement, so any single high score
    dominates while multiple moderate scores compound.

    Args:
        scores: The individual pattern scores to combine, each clamped
            to [0.0, 1.0] before combination.

    Returns:
        The combined score, rounded to 4 decimal places.
    """

    result = 1.0

    for score in scores:
        score = min(max(score, 0.0), 1.0)
        result *= (1 - score)

    return round(1 - result, 4)


def clamp(score: float) -> float:
    """Clamp a score to a maximum of 1.0 and round it.

    Args:
        score: The score to clamp.

    Returns:
        `min(score, 1.0)`, rounded to 4 decimal places.
    """
    return round(min(score, 1.0), 4)


def classify_behavior(score: float) -> str:
    """Classify an overall behavior score into a risk label.

    Args:
        score: The aggregated behavior score.

    Returns:
        `"malicious"` if `score >= 0.7`, `"suspicious"` if
        `score >= 0.4`, otherwise `"benign"`.
    """

    if score >= 0.7:
        return "malicious"

    if score >= 0.4:
        return "suspicious"

    return "benign"


# ==================================================
# Feature Extraction
# ==================================================

def extract_features(events: list[dict[str, Any]]) -> dict[str, float]:
    """Extract behavioral features from a session's ordered events.

    Args:
        events: The session's ordered events.

    Returns:
        A dictionary mapping each feature name to its extracted value
        (0.0/1.0 for binary features, or a normalized count in
        [0.0, 1.0] for count-based features).
    """

    commands = [safe_cmd(event) for event in events]
    actions = [safe_action(event) for event in events]

    features = {

        # ==================================================
        # Reverse Shell
        # ==================================================

        "shell_present": binary_feature(
            any(any(s in c for s in SUSPICIOUS_SHELLS) for c in commands)
            or
            any("shell" in a for a in actions)
        ),

        "outbound_connection": binary_feature(
            any(any(t in c for t in NETWORK_TOOLS) for c in commands)
            or
            any(
                "netcat" in a
                or "remote code" in a
                or "reverse shell" in a
                or "outbound" in a
                for a in actions
            )
        ),

        "interactive_behavior": normalize_count(
            sum(
                1 for c in commands
                if any(s in c for s in SUSPICIOUS_SHELLS)
            )
            +
            sum(
                1 for a in actions
                if "shell" in a or "interactive" in a
            ),
            3
        ),

        "unusual_parent_process": binary_feature(
            any(
                "unexpected parent" in a
                or "unusual parent" in a
                or "spawned by" in a
                for a in actions
            )
        ),

        # ==================================================
        # Download & Execute
        # ==================================================

        "download_detected": binary_feature(
            any(any(t in c for t in DOWNLOAD_TOOLS) for c in commands)
            or
            any(
                "download" in a
                or "fetch" in a
                or "curl" in a
                or "wget" in a
                for a in actions
            )
        ),

        "file_write": binary_feature(
            any((">" in c or "tee" in c) for c in commands)
            or
            any(
                "write" in a
                or "drop" in a
                or "create file" in a
                for a in actions
            )
        ),

        "permission_change": binary_feature(
            any("chmod" in c for c in commands)
            or
            any(
                "chmod" in a
                or "permission change" in a
                for a in actions
            )
        ),

        "execution_detected": binary_feature(
            any(any(k in c for k in EXEC_KEYWORDS) for c in commands)
            or
            any(
                "execut" in a
                or "run" in a
                or "launch" in a
                or "code execution" in a
                for a in actions
            )
        ),

        "temporal_proximity": binary_feature(
            any(
                "execution" in a
                or "execute" in a
                for a in actions
            )
        ),

        # ==================================================
        # Reconnaissance
        # ==================================================

        "identity_commands": normalize_count(
            sum(
                1 for c in commands
                if "whoami" in c or "id" in c
            )
            +
            sum(
                1 for a in actions
                if "whoami" in a
                or "identity" in a
                or "recon" in a
            ),
            3
        ),

        "system_info_commands": normalize_count(
            sum(
                1 for c in commands
                if "uname" in c
            )
            +
            sum(
                1 for a in actions
                if "uname" in a
                or "system info" in a
                or "enumerate" in a
            ),
            2
        ),

        "process_listing": normalize_count(
            sum(
                1 for c in commands
                if "ps" in c
            )
            +
            sum(
                1 for a in actions
                if "process list" in a
                or "process enum" in a
            ),
            2
        ),

        "network_scanning": normalize_count(
            sum(
                1 for c in commands
                if "netstat" in c
                or "ifconfig" in c
                or c.strip().startswith("ss")
            )
            +
            sum(
                1 for a in actions
                if "scan" in a
                or "network enum" in a
                or "port" in a
            ),
            3
        ),

        "burst_density": normalize_count(
            len(events),
            8
        ),

        # ==================================================
        # Privilege Escalation
        # ==================================================

        "sudo_usage": binary_feature(
            any("sudo" in c for c in commands)
            or
            any(
                "sudo" in a
                or "privilege escalat" in a
                or "escalat" in a
                for a in actions
            )
        ),

        "permission_modification": binary_feature(
            any(
                "chmod" in c
                or "chown" in c
                for c in commands
            )
            or
            any(
                "chmod" in a
                or "chown" in a
                or "permission modif" in a
                for a in actions
            )
        ),

        "access_protected_paths": binary_feature(
            any(
                "/etc/" in c
                or "/root/" in c
                for c in commands
            )
            or
            any(
                "/etc/" in a
                or "/root/" in a
                or "sensitive path" in a
                for a in actions
            )
        ),

        "capability_change": binary_feature(
            any("setcap" in c for c in commands)
            or
            any(
                "setcap" in a
                or "capabilit" in a
                for a in actions
            )
        ),

        "suspicious_parent_chain": binary_feature(
            any(
                "unexpected" in a
                or "suspicious parent" in a
                or "unusual chain" in a
                for a in actions
            )
        ),

        # ==================================================
        # Lateral Movement
        # ==================================================

        "remote_connection": binary_feature(
            any(
                "ssh" in c
                or "scp" in c
                for c in commands
            )
            or
            any(
                "ssh" in a
                or "lateral" in a
                or "remote connect" in a
                or "pivot" in a
                for a in actions
            )
        ),

        "credential_access": binary_feature(
            any(
                "/etc/passwd" in c
                or "/etc/shadow" in c
                or "/etc/sudoers" in c
                or "id_rsa" in c
                for c in commands
            )
            or
            any(
                "credential" in a
                or "passwd" in a
                or "shadow" in a
                for a in actions
            )
        ),

        "multi_target_attempts": normalize_count(
            sum(1 for c in commands if "ssh" in c)
            +
            sum(
                1 for a in actions
                if "lateral" in a or "multi" in a
            ),
            3
        ),

        "unusual_internal_paths": binary_feature(
            any(
                "/mnt/" in c
                or "/srv/" in c
                for c in commands
            )
            or
            any(
                "/mnt/" in a
                or "/srv/" in a
                for a in actions
            )
        ),

        # ==================================================
        # Data Exfiltration
        # ==================================================

        "large_data_read": normalize_count(
            sum(
                1 for c in commands
                if (
                     "/etc/passwd" in c
                      or "/etc/shadow" in c
                      or "tar" in c
                      or "zip" in c
                      or "gzip" in c
                )
            ),
            3
        ),

        "compression_activity": binary_feature(
            any(
                "zip" in c
                or "gzip" in c
                or "tar" in c
                for c in commands
            )
            or
            any(
                "compress" in a
                or "zip" in a
                or "tar" in a
                for a in actions
            )
        ),

        "outbound_transfer": binary_feature(
            any(
                "scp" in c
                or "rsync" in c
                for c in commands
            )
            or
            any(
                "exfil" in a
                or "transfer" in a
                or "upload" in a
                or "outbound" in a
                for a in actions
            )
        ),

        "unusual_destination": binary_feature(
            any(
                "unusual dest" in a
                or "external ip" in a
                or "c2" in a
                or "command and control" in a
                for a in actions
            )
        ),

        # ==================================================
        # Persistence
        # ==================================================

        "cron_modification": binary_feature(
            any("crontab" in c for c in commands)
            or
            any(
                "cron" in a
                or "scheduled task" in a
                for a in actions
            )
        ),

        "startup_script_edit": binary_feature(
            any(
                ".bashrc" in c
                or ".profile" in c
                for c in commands
            )
            or
            any(
                ".bashrc" in a
                or ".profile" in a
                or "startup" in a
                for a in actions
            )
        ),

        "service_creation": binary_feature(
            any(
                "systemctl" in c
                or "service" in c
                for c in commands
            )
            or
            any(
                "systemctl" in a
                or "service creat" in a
                or "daemon" in a
                for a in actions
            )
        ),

        "hidden_binary_drop": binary_feature(
            any("/tmp/" in c for c in commands)
            or
            any(
                "/tmp/" in a
                or "hidden binary" in a
                or "drop" in a
                for a in actions
            )
        ),

        # ==================================================
        # Container Escape
        # ==================================================

        "host_namespace_access": binary_feature(
            any(
                "/proc" in c
                or "/sys" in c
                for c in commands
            )
            or
            any(
                "/proc" in a
                or "/sys" in a
                or "namespace" in a
                or "host access" in a
                for a in actions
            )
        ),

        "privileged_container_usage": binary_feature(
            any("--privileged" in c for c in commands)
            or
            any(
                "privileged" in a
                or "privileged container" in a
                for a in actions
            )
        ),

        "sensitive_mount_access": binary_feature(
            any("docker.sock" in c for c in commands)
            or
            any(
                "docker.sock" in a
                or "mount" in a
                or "sensitive mount" in a
                for a in actions
            )
        ),

        "kernel_interaction": binary_feature(
            any("modprobe" in c for c in commands)
            or
            any(
                "modprobe" in a
                or "kernel" in a
                or "kernel module" in a
                for a in actions
            )
        ),
    }

    return features


# ==================================================
# Pattern Scoring
# ==================================================

def score_patterns(f: dict[str, float]) -> dict[str, float]:
    """Score named attack-pattern categories from extracted features.

    Weighting strategy:
        Each pattern's score is a fixed weighted sum of its contributing
        features (weights below are chosen so each pattern's base
        weights sum to 1.0), plus an additive "chain bonus" for
        patterns where two or more supporting features co-occur in a
        way that suggests a multi-step attack progression (e.g.
        download followed by execution, or a shell paired with an
        outbound connection). The result is clamped to [0.0, 1.0] via
        `clamp()`.

    Args:
        f: The feature dictionary as produced by `extract_features`.

    Returns:
        A dictionary mapping each pattern name (`reverse_shell`,
        `download_execute`, `reconnaissance`, `privilege_escalation`,
        `lateral_movement`, `data_exfiltration`, `persistence`,
        `container_escape`) to its clamped score in [0.0, 1.0].
    """

    # ==================================================
    # Behavioral Chain Bonuses
    # ==================================================

    chain_bonus = {
        "reverse_shell": 0.0,
        "download_execute": 0.0,
        "privilege_escalation": 0.0,
        "lateral_movement": 0.0,
        "data_exfiltration": 0.0,
        "persistence": 0.0,
        "container_escape": 0.0
    }

    # ==================================================
    # Download → Execute progression
    # ==================================================

    if (
        f["download_detected"]
        and
        f["execution_detected"]
    ):
        chain_bonus["download_execute"] += 0.15

    if (
        f["download_detected"]
        and
        f["permission_change"]
        and
        f["execution_detected"]
    ):
        chain_bonus["download_execute"] += 0.20

    # ==================================================
    # Reverse shell progression
    # ==================================================

    if (
        f["shell_present"]
        and
        f["outbound_connection"]
    ):
        chain_bonus["reverse_shell"] += 0.20

    if (
        f["shell_present"]
        and
        f["outbound_connection"]
        and
        f["interactive_behavior"]
    ):
        chain_bonus["reverse_shell"] += 0.15

    # ==================================================
    # Recon → Lateral movement
    # ==================================================

    if (
        f["identity_commands"]
        and
        f["network_scanning"]
    ):
        chain_bonus["lateral_movement"] += 0.10

    # ==================================================
    # Credential access → Remote connection
    # ==================================================

    if (
        f["credential_access"]
        and
        f["remote_connection"]
    ):
        chain_bonus["lateral_movement"] += 0.20

    # ==================================================
    # Final Pattern Scores
    # ==================================================
    return {

        "reverse_shell": clamp(
            (
                0.35 * f["shell_present"] +
                0.35 * f["outbound_connection"] +
                0.20 * f["interactive_behavior"] +
                0.10 * f["unusual_parent_process"]
            )
            + chain_bonus["reverse_shell"]
        ),

        "download_execute": clamp(
            (
                0.25 * f["download_detected"] +
                0.20 * f["file_write"] +
                0.15 * f["permission_change"] +
                0.30 * f["execution_detected"] +
                0.10 * f["temporal_proximity"]
            )
            + chain_bonus["download_execute"]
        ),

        "reconnaissance": clamp(
            (
                0.25 * f["identity_commands"] +
                0.25 * f["system_info_commands"] +
                0.20 * f["process_listing"] +
                0.30 * f["network_scanning"]
            )
        ),

        "privilege_escalation": clamp(
            (
                0.25 * f["sudo_usage"] +
                0.20 * f["permission_modification"] +
                0.25 * f["access_protected_paths"] +
                0.20 * f["capability_change"] +
                0.10 * f["suspicious_parent_chain"]
            )
            + chain_bonus["privilege_escalation"]
        ),

        "lateral_movement": clamp(
            (
                0.30 * f["remote_connection"] +
                0.25 * f["credential_access"] +
                0.25 * f["multi_target_attempts"] +
                0.20 * f["unusual_internal_paths"]
            )
            + chain_bonus["lateral_movement"]
        ),

        "data_exfiltration": clamp(
            (
                0.25 * f["large_data_read"] +
                0.20 * f["compression_activity"] +
                0.35 * f["outbound_transfer"] +
                0.20 * f["unusual_destination"]
            )
        ),

        "persistence": clamp(
            (
                0.30 * f["cron_modification"] +
                0.25 * f["startup_script_edit"] +
                0.25 * f["service_creation"] +
                0.20 * f["hidden_binary_drop"]
            )
        ),

        "container_escape": clamp(
            (
                0.30 * f["host_namespace_access"] +
                0.25 * f["privileged_container_usage"] +
                0.25 * f["sensitive_mount_access"] +
                0.20 * f["kernel_interaction"]
            )
        )
    }

# ==================================================
# Analysis Engine
# ==================================================

def calculate_behavior_score(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute the overall behavior score and label for a session's events.

    Args:
        events: The session's ordered events.

    Returns:
        A dictionary with `behavior_score`, `behavior_label`,
        `pattern_scores` (all pattern scores), and `patterns_detected`
        (pattern names scoring at or above 0.4).
    """

    features = extract_features(events)

    pattern_scores = score_patterns(features)

    patterns_detected = [
        pattern_name for pattern_name, score in pattern_scores.items()
        if score >= 0.4
    ]
    active_patterns = {
        pattern_name: score
        for pattern_name, score in pattern_scores.items()
        if score >= 0.2
    }

    behavior_score = (
        aggregate_scores(active_patterns.values())
        if active_patterns
        else 0.0
    )

    behavior_label = classify_behavior(behavior_score)

    return {
        "behavior_score": behavior_score,
        "behavior_label": behavior_label,
        "pattern_scores": pattern_scores,
        "patterns_detected": patterns_detected
    }


def analyze_sessions(sessions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Run behavior analysis over a list of sessions.

    Args:
        sessions: Sessions to analyze, each with `session_id`, `user`,
            and `ordered_events`.

    Returns:
        A list of per-session behavior analysis results.
    """

    results = []

    for session in sessions:

        result = calculate_behavior_score(
            session["ordered_events"]
        )

        results.append({
            "session_id": session["session_id"],
            "user": session["user"],
            "behavior_score": result["behavior_score"],
            "behavior_label": result["behavior_label"],
            "pattern_scores": result["pattern_scores"],
            "patterns_detected": result["patterns_detected"]
        })

    return results


# ==================================================
# Main
# ==================================================

def main() -> None:
    sessions = load_json(SESSIONS_PATH)

    analyzed_sessions = analyze_sessions(sessions)

    save_json(BEHAVIOR_ANALYSIS_PATH, analyzed_sessions)

    print("Behavior analysis complete.")


if __name__ == "__main__":
    main()
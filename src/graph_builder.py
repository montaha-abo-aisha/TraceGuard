"""Build behavioral session graphs from sessionized security events.

This module is part of the TraceGuard behavioral security analytics
pipeline. It consumes sessions (as produced by the sessionization
stage), classifies each event's process/command into semantic action
categories, builds a per-session graph of nodes (events) and typed
edges (temporal, process-continuity, semantic-transition, and
burst-proximity relationships), and derives adjacency/process
relationship matrices and high-weight paths through the graph. The
output feeds the downstream confidence-scoring and behavior-analysis
stages.

The output schema (session graph dictionary structure, node/edge
fields, and matrix formats) is relied upon by other TraceGuard
pipeline modules and must remain unchanged.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

# =========================================================
# PATHS
# =========================================================

from config import (
    SESSIONS_PATH,
    SESSION_GRAPHS_PATH,
)
JSON_INDENT = 2


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
        json.dump(data, f, indent=JSON_INDENT)


# =========================================================
# CONFIG
# =========================================================

EDGE_WEIGHTS = {
    "temporal": 1.0,
    "process_continuity": 2.0,
    "burst_proximity": 1.5
}

SEMANTIC_RELATIONS = {
    ("shell", "runtime_execution"):              4.0,
    ("network_request", "shell"):                3.5,
    ("permission_change", "runtime_execution"):  3.0,
    ("file_read", "runtime_execution"):          2.5,
    ("system_info", "network_tool"):             2.0,
}

BURST_WINDOW         = 60
MAX_PATH_DEPTH       = 5
MAX_PATHS            = 50
MIN_PATH_WEIGHT      = 3.0
PATH_DIVERSITY_BONUS = 0.15

SEMANTIC_MAX_CAP = 5.0   # Prevents semantic weight from growing without bound.

PATH_WEIGHT_PRECISION = 2
PROCESS_MATRIX_PRECISION = 4


# =========================================================
# FALCO ACTION MAPPING
# =========================================================

FALCO_ACTION_MAPPING = {
    "netcat remote code execution in container": [
        "network_tool",
        "runtime_execution",
        "shell"
    ],

    "terminal shell in container": [
        "shell"
    ],

    "unexpected outbound connection": [
        "network_request"
    ],

    "sensitive file opened for reading": [
        "file_read"
    ],

    "privilege escalation": [
        "permission_change"
    ]
}


# =========================================================
# VALIDATION
# =========================================================

def validate_event(event: dict[str, Any], index: int) -> None:
    """Validate that an event has a usable numeric timestamp.

    Args:
        event: The event dictionary to validate.
        index: The event's position in its session, used for error
            reporting.

    Raises:
        ValueError: If `event`'s timestamp is missing or not numeric.
    """
    timestamp = event.get("timestamp")
    if not isinstance(timestamp, (int, float)):
        raise ValueError(
            f"Event at index {index} has invalid timestamp: {repr(timestamp)}"
        )


# =========================================================
# CLASSIFICATION
# =========================================================

def classify_action(cmd: str = "", falco_action: str = "") -> list[str]:
    """Classify a command line or Falco action into semantic action tags.

    Args:
        cmd: The process command line, if available.
        falco_action: The Falco rule name/action, used when no command
            line is available.

    Returns:
        A list of semantic action tags (e.g. "shell", "network_request"),
        or ``["unknown"]`` if nothing could be classified.
    """
    cmd = (cmd or "").lower()
    falco_action = (falco_action or "").lower()

    actions = []

    # -----------------------------------------
    # Falco rules take priority if no command
    # -----------------------------------------
    if not cmd and falco_action:
        return FALCO_ACTION_MAPPING.get(
            falco_action,
            ["unknown"]
        )

    # -----------------------------------------
    # Command-based classification
    # -----------------------------------------

    if any(x in cmd for x in ["curl", "wget", "http://", "https://"]):
        actions.append("network_request")

    if any(x in cmd for x in ["ssh", "scp", "rsync", "nc", "netcat"]):
        actions.append("network_tool")

    if any(x in cmd for x in ["bash", "sh ", "/bin/sh", "/bin/bash", "zsh"]):
        actions.append("shell")

    if any(x in cmd for x in ["python", "perl", "ruby", "php", "node"]):
        actions.append("runtime_execution")

    if any(x in cmd for x in ["chmod", "chown", "setcap"]):
        actions.append("permission_change")

    if any(x in cmd for x in ["ps", "whoami", "id", "uname", "netstat", "ss"]):
        actions.append("system_info")

    if any(x in cmd for x in ["cat", "less", "head", "tail"]):
        actions.append("file_read")

    # Executed scripts
    if cmd.startswith("./"):
        actions.append("runtime_execution")

    return list(dict.fromkeys(actions)) if actions else ["unknown"]


# =========================================================
# NODE
# =========================================================

def build_node(event: dict[str, Any], idx: int) -> dict[str, Any]:
    """Build a graph node dictionary from a single session event.

    Args:
        event: The source event (auditd or correlated Falco event).
        idx: The node's sequence number within the session, used to
            build its `node_id`.

    Returns:
        A node dictionary with identity, timing, process, and
        classified-action fields.
    """
    cmd = event.get("proc_cmdline", "")
    falco_action = event.get("action", "")

    process = event.get("proc_name")

    if not process:
        process = falco_action if falco_action else "unknown"

    return {
        "node_id": f"n{idx}",
        "timestamp": event.get("timestamp"),
        "process": process,
        "cmd": cmd,
        "actions": classify_action(cmd, falco_action)
    }


# =========================================================
# EDGE LOGIC
# =========================================================

def get_semantic_weight(actions_a: list[str], actions_b: list[str]) -> float:
    """Compute the total semantic-transition weight between two action sets.

    Args:
        actions_a: Semantic action tags for the source node.
        actions_b: Semantic action tags for the target node.

    Returns:
        The summed weight of all known `(action_a, action_b)` relations
        between the two sets, capped at `SEMANTIC_MAX_CAP`.
    """
    total = 0.0

    for act_a in actions_a:
        for act_b in actions_b:
            total += SEMANTIC_RELATIONS.get((act_a, act_b), 0.0)

    return min(total, SEMANTIC_MAX_CAP)


def build_edges(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build typed edges between consecutive nodes in a session.

    For each pair of consecutive nodes, this may emit a temporal edge,
    a process-continuity edge, a semantic-transition edge, and/or a
    burst-proximity edge, depending on the nodes' timing, process
    identity, and classified actions.

    Args:
        nodes: The session's nodes, in chronological order.

    Returns:
        The list of edges connecting consecutive nodes.
    """
    edges = []

    for i in range(len(nodes) - 1):
        node_a = nodes[i]
        node_b = nodes[i + 1]
        time_gap = node_b["timestamp"] - node_a["timestamp"]

        # temporal
        edges.append({
            "source": node_a["node_id"],
            "target": node_b["node_id"],
            "type": "temporal",
            "weight": EDGE_WEIGHTS["temporal"],
            "time_gap": time_gap
        })

        # same process
        if node_a["process"] == node_b["process"]:
            edges.append({
                "source": node_a["node_id"],
                "target": node_b["node_id"],
                "type": "process_continuity",
                "weight": EDGE_WEIGHTS["process_continuity"],
                "time_gap": time_gap
            })

        # semantic
        semantic_weight = get_semantic_weight(node_a["actions"], node_b["actions"])
        if semantic_weight > 0:
            edges.append({
                "source": node_a["node_id"],
                "target": node_b["node_id"],
                "type": "semantic_transition",
                "weight": semantic_weight,
                "time_gap": time_gap
            })

        # burst
        if (
            time_gap <= BURST_WINDOW
            and node_a["process"] != node_b["process"]
            and "unknown" not in node_a["actions"]
            and "unknown" not in node_b["actions"]
        ):
            edges.append({
                "source": node_a["node_id"],
                "target": node_b["node_id"],
                "type": "burst_proximity",
                "weight": EDGE_WEIGHTS["burst_proximity"],
                "time_gap": time_gap
            })

    return edges


# =========================================================
# MATRICES
# =========================================================

def build_adjacency_matrix(
    nodes: list[dict[str, Any]], edges: list[dict[str, Any]]
) -> list[list[float]]:
    """Build a weighted node-to-node adjacency matrix.

    Args:
        nodes: The session's nodes.
        edges: The session's edges.

    Returns:
        An `n x n` matrix (where `n = len(nodes)`) with summed edge
        weights between each pair of nodes.
    """
    node_count = len(nodes)
    node_index = {node["node_id"]: i for i, node in enumerate(nodes)}
    matrix = [[0.0] * node_count for _ in range(node_count)]

    for edge in edges:
        matrix[node_index[edge["source"]]][node_index[edge["target"]]] += edge["weight"]

    return matrix


def build_process_relationship_matrix(
    nodes: list[dict[str, Any]], edges: list[dict[str, Any]]
) -> dict[str, Any]:
    """Build a normalized process-to-process relationship matrix.

    Args:
        nodes: The session's nodes.
        edges: The session's edges.

    Returns:
        A dictionary with the sorted list of distinct process names and
        their corresponding weight matrix, normalized so entries are a
        proportion of the total edge weight (unless total weight is 0,
        in which case raw zeroed weights are returned unnormalized).
    """
    processes = sorted(set(n["process"] for n in nodes))
    process_index = {p: i for i, p in enumerate(processes)}

    matrix = [[0.0] * len(processes) for _ in processes]
    node_lookup = {node["node_id"]: node for node in nodes}

    total_weight = 0.0

    for edge in edges:
        process_a = node_lookup[edge["source"]]["process"]
        process_b = node_lookup[edge["target"]]["process"]

        matrix[process_index[process_a]][process_index[process_b]] += edge["weight"]
        total_weight += edge["weight"]

    # Normalize edge weights so each entry reflects its proportion of
    # the session's total edge weight, rather than a raw sum.
    if total_weight > 0:
        matrix = [
            [round(weight / total_weight, PROCESS_MATRIX_PRECISION) for weight in row]
            for row in matrix
        ]

    return {
        "processes": processes,
        "matrix": matrix
    }


# =========================================================
# PATH EXTRACTION
# =========================================================

def calculate_path_weight(
    path_nodes: list[str],
    adjacency_with_types: dict[str, list[tuple[str, float, str]]],
) -> float:
    """Calculate the total weight of a path, with a path-diversity bonus.

    Args:
        path_nodes: The ordered node IDs making up the path.
        adjacency_with_types: Mapping from a source node ID to a list of
            `(target_node_id, weight, edge_type)` tuples.

    Returns:
        The path's total weight, boosted by `PATH_DIVERSITY_BONUS` if
        the path traverses more than one distinct edge type, rounded to
        2 decimal places.
    """
    total_weight = 0.0
    edge_types_seen = set()

    for i in range(len(path_nodes) - 1):
        src = path_nodes[i]
        tgt = path_nodes[i + 1]

        for target, weight, edge_type in adjacency_with_types.get(src, []):
            if target == tgt:
                total_weight += weight
                edge_types_seen.add(edge_type)
                break

    if len(edge_types_seen) > 1:
        total_weight *= (1 + PATH_DIVERSITY_BONUS)

    return round(total_weight, PATH_WEIGHT_PRECISION)


def extract_paths(
    nodes: list[dict[str, Any]], edges: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Extract high-weight paths through the session graph via DFS.

    Starting from every node, performs a depth-first search (bounded by
    `MAX_PATH_DEPTH`) preferring higher-weight edges first, keeping any
    resulting path whose weight meets `MIN_PATH_WEIGHT`, until at most
    `MAX_PATHS` paths have been collected.

    Args:
        nodes: The session's nodes.
        edges: The session's edges.

    Returns:
        Up to `MAX_PATHS` paths, sorted by descending weight, each as a
        dict with `path` (ordered node IDs) and `weight`.
    """
    adjacency: defaultdict[str, list[tuple[str, float]]] = defaultdict(list)
    adjacency_with_types: defaultdict[str, list[tuple[str, float, str]]] = defaultdict(list)

    for edge in edges:
        adjacency[edge["source"]].append((edge["target"], edge["weight"]))
        adjacency_with_types[edge["source"]].append(
            (edge["target"], edge["weight"], edge["type"])
        )

    paths = []

    def dfs(current: str, path: list[str]) -> None:
        if len(paths) >= MAX_PATHS:
            return

        next_nodes = adjacency.get(current, [])

        if len(path) >= MAX_PATH_DEPTH or not next_nodes:
            final_weight = calculate_path_weight(path, adjacency_with_types)
            if final_weight >= MIN_PATH_WEIGHT:
                paths.append({"path": path[:], "weight": final_weight})
            return

        for next_node, _ in sorted(next_nodes, key=lambda entry: -entry[1]):
            if next_node not in path:
                dfs(next_node, path + [next_node])

    for node in nodes:
        dfs(node["node_id"], [node["node_id"]])

    paths.sort(key=lambda x: -x["weight"])
    return paths[:MAX_PATHS]


# =========================================================
# SESSION GRAPH
# =========================================================

def build_session_graph(session: dict[str, Any]) -> dict[str, Any]:
    """Build the full behavioral graph for a single session.

    Args:
        session: A session dictionary (as produced by the
            sessionization stage), containing `session_id` and
            `ordered_events`.

    Returns:
        A dictionary with the session's ID, nodes, edges, adjacency
        matrix, process relationship matrix, and extracted high-weight
        paths.
    """
    events = sorted(session["ordered_events"], key=lambda x: x["timestamp"])

    for i, event in enumerate(events):
        validate_event(event, i)

    nodes = [build_node(event, i + 1) for i, event in enumerate(events)]
    edges = build_edges(nodes)

    return {
        "session_id": session["session_id"],
        "nodes": nodes,
        "edges": edges,
        "adjacency_matrix": build_adjacency_matrix(nodes, edges),
        "process_relationship_matrix": build_process_relationship_matrix(nodes, edges),
        "paths": extract_paths(nodes, edges)
    }


# =========================================================
# MAIN
# =========================================================

def main() -> None:
    sessions = load_json(SESSIONS_PATH)

    graphs = [build_session_graph(s) for s in sessions]

    save_json(SESSION_GRAPHS_PATH, graphs)

    print("Graph builder completed.")


if __name__ == "__main__":
    main()
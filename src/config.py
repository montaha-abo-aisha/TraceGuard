"""Shared path configuration for the TraceGuard pipeline.

Every pipeline module (Normalization, Correlation, sessionization,
graph_builder, confidence_calculation, Risk_Engine) imports its input
and output paths from here instead of hardcoding them individually.
This keeps the pipeline portable across machines and lets you switch
between demo scenarios without touching any pipeline code.

Usage:
    # Run against the default scenario ("clean_attack"):
    python Normalization.py

    # Run against a different scenario folder under data/sample_scenarios/:
    TRACEGUARD_SCENARIO=other_scenario python Normalization.py
"""

from __future__ import annotations

import os
from pathlib import Path

# ==================================================
# Project root — resolved automatically, no hardcoded machine paths
# ==================================================
PROJECT_ROOT = Path(__file__).resolve().parent

# ==================================================
# Active scenario — defaults to "clean_attack", overridable via env var
# ==================================================
SCENARIO = os.environ.get("TRACEGUARD_SCENARIO", "clean_attack")

# All input and output files for a given run live together in one
# scenario folder: data/sample_scenarios/<SCENARIO>/
DATA_DIR = PROJECT_ROOT / "data" / "sample_scenarios" / SCENARIO

# ==================================================
# Raw inputs (provided by you, one pair per scenario)
# ==================================================
RAW_AUDIT_PATH = DATA_DIR / "audit.json"
RAW_FALCO_PATH = DATA_DIR / "falco.json"

# ==================================================
# Pipeline stage outputs (each stage reads the previous stage's output)
# ==================================================
NORMALIZED_AUDIT_PATH = DATA_DIR / "normalized_audit.json"
NORMALIZED_FALCO_PATH = DATA_DIR / "normalized_falco.json"
CORRELATED_EVENTS_PATH = DATA_DIR / "correlated_events.json"
SESSIONS_PATH = DATA_DIR / "sessions.json"
SESSION_GRAPHS_PATH = DATA_DIR / "session_graphs.json"
CONFIDENCE_RESULTS_PATH = DATA_DIR / "confidence_results.json"
BEHAVIOR_ANALYSIS_PATH = DATA_DIR / "behavior_analysis.json"
RISK_SCORES_PATH = DATA_DIR / "risk_scores.json"

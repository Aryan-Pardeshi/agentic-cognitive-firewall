"""Tests for the AgentDojo latency tool's arithmetic and report."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
pytest.importorskip("agentdojo.agent_pipeline")

import latency_agentdojo as lat  # noqa: E402


def test_describe_reports_percentiles_of_the_samples():
    row = lat.describe([float(v) for v in range(1, 101)])
    assert row == {"n": 100, "p50_ms": 50.5, "p95_ms": 96.0, "p99_ms": 100.0, "max_ms": 100.0}


def test_render_markdown_names_the_conditions():
    summary = {
        "runs": 3, "acf_commit": "abc", "ms_per_case": 6.1,
        "machine": {"processor": "cpu", "platform": "os", "on_mains_power": True},
        "hooks": {"on_tool_call": {"n": 10, "p50_ms": 0.5, "p95_ms": 1.0, "p99_ms": 2.0, "max_ms": 3.0}},
        "tool_result_bytes": {"p50": 272, "p99": 29477, "max": 30283},
        "sidecar_memory": {"per_process_mb": 75.0, "total_mb": 300.0, "processes": 4},
    }
    text = lat.render_markdown(summary)
    assert "mains power: True" in text and "| on_tool_call | 10 | 0.5 | 1.0 | 2.0 | 3.0 |" in text
    assert "75.0 MB per process" in text

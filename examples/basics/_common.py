"""Shared helpers for the basic examples: console encoding and a checked print."""
from __future__ import annotations

import sys

# Windows consoles default to a legacy code page; make printing safe everywhere.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

_results: list[bool] = []


def check(label: str, result, expected) -> None:
    """Print one decision against the expected one and remember the outcome."""
    decision = getattr(result, "decision", result)
    ok = decision == expected
    _results.append(ok)
    print(f"  [{'ok' if ok else 'FAIL'}] {label:<52} -> {decision.name}"
          + ("" if ok else f" (expected {expected.name})"))
    text = getattr(result, "sanitised_text", None)
    if text:
        print(f"         sanitised to {text[:60]!r}")


def summary() -> None:
    print("\nPASS" if all(_results) else "\nFAIL")
    sys.exit(0 if all(_results) else 1)

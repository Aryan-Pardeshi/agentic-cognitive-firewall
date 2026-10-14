#!/usr/bin/env python3
"""Latency of ACF's hooks on AgentDojo's own payloads, in the full configuration.

benchmarkv2/overhead measures single hook calls without session state. This
measures the configuration the AgentDojo evaluation uses: every case of the
model-free replay in the full-task-taint arm (a session, a declared task scope,
tool-output screening and argument tainting), one case at a time, timing each
SDK call. It also samples the sidecar processes' memory.

    python latency_agentdojo.py --runs 3

Writes results/<UTC timestamp>-latency/summary.json and summary.md. Run on mains
power with the machine otherwise idle; the summary records whether it was.
"""
from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import acf_guard  # noqa: E402
import run_agentdojo  # noqa: E402

HOOKS = ("on_task", "on_prompt", "on_tool_call", "on_tool_result")


def percentile(values: list[float], q: float) -> float:
    ordered = sorted(values)
    return ordered[min(int(len(ordered) * q), len(ordered) - 1)]


def describe(values: list[float]) -> dict[str, Any]:
    return {
        "n": len(values),
        "p50_ms": round(statistics.median(values), 3),
        "p95_ms": round(percentile(values, 0.95), 3),
        "p99_ms": round(percentile(values, 0.99), 3),
        "max_ms": round(max(values), 3),
    }


def make_timed_guard(samples: dict[str, list[float]], sizes: list[int]) -> type:
    class TimedGuard(acf_guard.Guard):
        """The runner's Guard, with every SDK call on its session timed."""

        def __init__(self, firewall, arm, task_tools, confirmed_values=()):
            started = time.perf_counter_ns()
            super().__init__(firewall, arm, task_tools, confirmed_values)
            if self.session is None:
                return
            # Opening a session with a scope is one on_task request.
            samples["on_task"].append((time.perf_counter_ns() - started) / 1e6)
            for hook in HOOKS[1:]:
                original = getattr(self.session, hook)

                def timed(*args, _original=original, _hook=hook):
                    t0 = time.perf_counter_ns()
                    try:
                        return _original(*args)
                    finally:
                        samples[_hook].append((time.perf_counter_ns() - t0) / 1e6)
                        if _hook == "on_tool_result":
                            sizes.append(len(args[1].encode("utf-8")))

                setattr(self.session, hook, timed)

    return TimedGuard


class MemorySampler(threading.Thread):
    """Peak resident memory of the run's sidecar processes, once a second."""

    def __init__(self, binary: Path) -> None:
        super().__init__(daemon=True)
        import psutil  # noqa: PLC0415 — installed with agentdojo
        self.psutil = psutil
        self.binary = str(binary.resolve()).lower()
        self.peak_per_process_mb = 0.0
        self.peak_total_mb = 0.0
        self.processes = 0
        self.stopped = threading.Event()

    def run(self) -> None:
        while not self.stopped.is_set():
            rss = []
            for proc in self.psutil.process_iter(["exe"]):
                try:
                    if (proc.info["exe"] or "").lower() == self.binary:
                        rss.append(proc.memory_info().rss / 2**20)
                except (self.psutil.NoSuchProcess, self.psutil.AccessDenied):
                    continue
            if rss:
                self.peak_per_process_mb = max(self.peak_per_process_mb, max(rss))
                self.peak_total_mb = max(self.peak_total_mb, sum(rss))
                self.processes = max(self.processes, len(rss))
            self.stopped.wait(1.0)


def on_mains_power() -> bool | None:
    try:
        import psutil  # noqa: PLC0415
        battery = psutil.sensors_battery()
    except Exception:  # noqa: BLE001 — no sensor support on this platform
        return None
    return None if battery is None else bool(battery.power_plugged)


def render_markdown(summary: dict[str, Any]) -> str:
    lines = [
        "# ACF hook latency on AgentDojo payloads",
        "",
        f"Arm `full-task-taint`, model-free replay, one case at a time, {summary['runs']} run(s). "
        f"{summary['machine']['processor']}, {summary['machine']['platform']}, "
        f"mains power: {summary['machine']['on_mains_power']}. ACF commit `{summary['acf_commit']}`.",
        "",
        "Medians across runs of each run's percentile, in ms.",
        "",
        "| Hook | Calls per run | p50 | p95 | p99 | max |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for hook, row in summary["hooks"].items():
        lines.append(f"| {hook} | {row['n']} | {row['p50_ms']} | {row['p95_ms']} | {row['p99_ms']} | {row['max_ms']} |")
    tool = summary["tool_result_bytes"]
    mem = summary["sidecar_memory"]
    lines += [
        "",
        f"Tool results: p50 {tool['p50']} B, p99 {tool['p99']} B, max {tool['max']} B. "
        f"ACF time per case: {summary['ms_per_case']} ms.",
        f"Sidecar memory, peak resident: {mem['per_process_mb']} MB per process "
        f"({mem['processes']} processes, one per suite configuration).",
        "",
    ]
    return "\n".join(lines)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--results-dir", type=Path, default=HERE / "results")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if on_mains_power() is False:
        print("warning: running on battery; latency is typically two to three times higher than on "
              "mains power, so these figures are not comparable with a run on mains power", flush=True)
    out_dir = args.results_dir / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-latency")
    work = out_dir / "work"
    per_run: list[dict[str, Any]] = []
    sizes: list[int] = []
    memory = {"per_process_mb": 0.0, "total_mb": 0.0, "processes": 0}
    cases = 0
    for run in range(1, args.runs + 1):
        samples: dict[str, list[float]] = {hook: [] for hook in HOOKS}
        run_agentdojo.Guard = make_timed_guard(samples, sizes if run == 1 else [])
        sampler = MemorySampler(run_agentdojo.DEFAULT_BINARY)
        sampler.start()
        code = run_agentdojo.main(["--mode", "replay", "--arms", "full-task-taint", "--workers", "1",
                                   "--results-dir", str(work / f"run{run}")])
        sampler.stopped.set()
        sampler.join()
        if code != 0:
            raise SystemExit(f"replay run {run} failed with exit code {code}")
        cases = len(samples["on_prompt"])
        all_calls = [value for hook in HOOKS for value in samples[hook]]
        per_run.append({**{hook: describe(samples[hook]) for hook in HOOKS},
                        "all hooks": describe(all_calls),
                        "ms_per_case": sum(all_calls) / max(cases, 1)})
        memory = {
            "per_process_mb": round(max(memory["per_process_mb"], sampler.peak_per_process_mb), 1),
            "total_mb": round(max(memory["total_mb"], sampler.peak_total_mb), 1),
            "processes": max(memory["processes"], sampler.processes),
        }

    hooks = {
        hook: {"n": per_run[0][hook]["n"],
               **{key: round(statistics.median(r[hook][key] for r in per_run), 3)
                  for key in ("p50_ms", "p95_ms", "p99_ms", "max_ms")}}
        for hook in (*HOOKS, "all hooks")
    }
    provenance = json.loads(next(work.glob("run1/*/summary.json")).read_text(encoding="utf-8"))["provenance"]
    summary = {
        "runs": args.runs,
        "cases_per_run": cases,
        "acf_commit": provenance.get("acf_commit"),
        "acf_tree_dirty": provenance.get("acf_tree_dirty"),
        "machine": {"processor": platform.processor() or platform.machine(),
                    "platform": platform.platform(), "on_mains_power": on_mains_power()},
        "hooks": hooks,
        "per_run": per_run,
        "ms_per_case": round(statistics.median(r["ms_per_case"] for r in per_run), 2),
        "tool_result_bytes": {"p50": percentile(sizes, 0.5), "p99": percentile(sizes, 0.99), "max": max(sizes)},
        "sidecar_memory": memory,
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=1) + "\n", encoding="utf-8")
    (out_dir / "summary.md").write_text(render_markdown(summary), encoding="utf-8")
    print(render_markdown(summary))
    print(f"results: {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

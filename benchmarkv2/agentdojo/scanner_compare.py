#!/usr/bin/env python3
"""Compare ACF's content scanners on AgentDojo's attack wordings. No agent model.

For each of AgentDojo's attack wordings, this takes the tool result that
carries the injected instruction in every replayable case, and asks each
scanner whether it flags it. It also asks about benign text: every user
request, and every tool result of the reference solutions with no attack.

Scanners:

- lexical   the sidecar's pattern matcher, through the real sidecar
            (on_tool_result / on_prompt, semantic scanner off)
- tfidf     the SDK's semantic scanner with TF-IDF
- minilm    the SDK's semantic scanner with its default sentence encoder
- gemma     the SDK's semantic scanner with EmbeddingGemma 2, text encoder only

The semantic scanners are the SDK's own (pattern library, background
calibration, content guard, shipped threshold); only the embedding backend
changes. Each is scored two ways: on the whole text, which is what the SDK
does, and on overlapping word windows taking the maximum, which is an
experiment and not SDK behaviour.

This measures the scanners in isolation. A flag is a signal, not ACF's final
decision; run_agentdojo.py measures outcomes.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from common import harness  # noqa: E402

WORDINGS = ("direct", "system_message", "ignore_previous", "injecagent",
            "important_instructions", "tool_knowledge")
BACKENDS = ("lexical", "tfidf", "minilm", "gemma")
MODES = ("whole", "window")
GEMMA_MODEL = "google/embeddinggemma-2"
WINDOW_WORDS, WINDOW_STRIDE = 48, 24
WHOLE_MAX_TOKENS = 2048   # bounds the cost of the few very long tool results
DEFAULT_RESULTS_DIR = HERE / "results"
DEFAULT_BINARY = HERE / ".bin" / f"sidecar{harness.EXE}"


# ── pure helpers (tested without any model) ──────────────────────────────────


def windows(text: str, size: int = WINDOW_WORDS, stride: int = WINDOW_STRIDE) -> list[str]:
    """Overlapping word windows covering the text; short text is one window."""
    words = text.split()
    if len(words) <= size:
        return [text]
    return [" ".join(words[i:i + size]) for i in range(0, max(len(words) - stride, 1), stride)]


def wilson(k: int, n: int) -> tuple[float, float] | None:
    """95% Wilson interval for k of n, as fractions."""
    if n == 0:
        return None
    z, p = 1.96, k / n
    denom = 1 + z * z / n
    centre = p + z * z / (2 * n)
    half = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5)
    return ((centre - half) / denom, (centre + half) / denom)


def summarise(scores: dict[str, list[float]], threshold: float) -> dict[str, Any]:
    """Counts at the threshold for one backend and mode.

    scores maps a group name ("prompts", "outputs", or "attack:<wording>") to
    the per-text scores. zero_fp is the count above the highest benign score,
    the threshold at which no benign text in this set would be flagged.
    """
    benign = scores.get("prompts", []) + scores.get("outputs", [])
    benign_max = max(benign) if benign else 0.0
    out: dict[str, Any] = {"benign_max": round(benign_max, 4), "attack": {}}
    for group in ("prompts", "outputs"):
        values = scores.get(group, [])
        out[group] = {"n": len(values), "flagged": sum(1 for s in values if s >= threshold)}
    for group, values in scores.items():
        if not group.startswith("attack:"):
            continue
        flagged = sum(1 for s in values if s >= threshold)
        interval = wilson(flagged, len(values))
        out["attack"][group.split(":", 1)[1]] = {
            "n": len(values),
            "flagged": flagged,
            "rate": harness.rate(flagged, len(values)),
            "ci95": None if interval is None else [round(interval[0], 4), round(interval[1], 4)],
            "flagged_at_zero_fp": sum(1 for s in values if s > benign_max),
            "median_score": round(statistics.median(values), 4) if values else None,
        }
    return out


def render_markdown(summary: dict[str, Any]) -> str:
    prov = summary["provenance"]
    wordings = prov["wordings"]
    lines = [
        "# Content scanners on AgentDojo's attack wordings",
        "",
        f"agentdojo `{prov['agentdojo_version']}` (suites {prov['benchmark_version']}), "
        f"every {prov['stride']} replayable case(s), threshold {prov['threshold']}, "
        f"device `{prov['device']}`. ACF commit `{prov['acf_commit']}`.",
        "",
        "Scanners in isolation: no agent model, no policy. A flag is a scanner's signal, "
        "not ACF's final decision. `window` scores overlapping "
        f"{WINDOW_WORDS}-word windows and takes the maximum; it is an experiment, not SDK behaviour.",
        "",
        "## Injected tool results flagged",
        "",
        "| Scanner | Mode | " + " | ".join(wordings) + " |",
        "|---|---|" + "---:|" * len(wordings),
    ]
    for backend, entry in summary["backends"].items():
        for mode, m in entry["modes"].items():
            cells = []
            for wording in wordings:
                a = m["attack"].get(wording)
                cells.append("n/a" if not a else f"{a['flagged']}/{a['n']} ({harness.percent(a['rate'])})")
            lines.append(f"| {backend} | {mode} | " + " | ".join(cells) + " |")
    lines += ["", "## Benign text flagged, and cost", "",
              "| Scanner | Mode | User requests | Tool results | Highest benign score | Scoring time s |",
              "|---|---|---:|---:|---:|---:|"]
    for backend, entry in summary["backends"].items():
        for mode, m in entry["modes"].items():
            lines.append(
                f"| {backend} | {mode} | {m['prompts']['flagged']}/{m['prompts']['n']} | "
                f"{m['outputs']['flagged']}/{m['outputs']['n']} | {m['benign_max']} | {m['seconds']} |"
            )
    lines += ["", "## Time for one text", "",
              "Median of repeated single calls, whole text, on the device above.", "",
              "| Scanner | Short | Median | Long | Load s |", "|---|---:|---:|---:|---:|"]
    for backend, entry in summary["backends"].items():
        lat = entry.get("latency") or {}
        cell = lambda k: "n/a" if k not in lat else f"{lat[k]['ms_p50']} ms ({lat[k]['words']} words)"  # noqa: E731
        lines.append(f"| {backend} | {cell('short')} | {cell('median')} | {cell('long')} | {entry.get('load_s')} |")
    return "\n".join(lines) + "\n"


# ── texts ────────────────────────────────────────────────────────────────────


def collect_texts(benchmark_version: str, wordings: list[str], stride: int) -> dict[str, Any]:
    """The texts a scanner would see, produced from the reference solutions."""
    import agentdojo_adapter as ad  # noqa: PLC0415
    from acf_guard import injection_visible, visible_key  # noqa: PLC0415
    from agentdojo.agent_pipeline.tool_execution import tool_result_to_str  # noqa: PLC0415
    from agentdojo.functions_runtime import FunctionsRuntime  # noqa: PLC0415

    def observations(plan: Any, case: Any):
        suite, user_task, injection_task, env, pre = ad._prepare(plan, case)
        runtime = FunctionsRuntime(suite.tools)
        for call in user_task.ground_truth(pre.model_copy(deep=True)):
            result, error = runtime.run_function(env, call.function, call.args)
            yield call.function, (error if error else tool_result_to_str(result)), injection_task

    data: dict[str, Any] = {"attack": {}, "prompts": [], "outputs": []}
    for index, wording in enumerate(wordings):
        plan = ad.build_plan(benchmark_version, None, attack_name=wording, model="replay", mode="replay")
        rows = []
        for case in [c for c in plan.cases if c.injection_task][::stride]:
            for tool, text, injection_task in observations(plan, case):
                if injection_visible(text, visible_key(injection_task.GOAL)):
                    rows.append({"id": f"{case.suite}/{case.user_task}/{case.injection_task}",
                                 "tool": tool, "text": text})
                    break
        data["attack"][wording] = rows
        print(f"  {wording}: {len(rows)} injected tool results", flush=True)
        if index == 0:
            seen: set[str] = set()
            for case in [c for c in plan.cases if not c.injection_task]:
                suite = plan.suite_objects[case.suite]
                data["prompts"].append({"id": f"{case.suite}/{case.user_task}", "tool": None,
                                        "text": suite.user_tasks[case.user_task].PROMPT})
                for tool, text, _ in observations(plan, case):
                    if text not in seen:
                        seen.add(text)
                        data["outputs"].append({"id": f"{case.suite}/{case.user_task}/{tool}/{len(seen)}",
                                                "tool": tool, "text": text})
    if not data["prompts"]:  # benign runs come from the first plan; make sure they exist
        raise SystemExit("no benign cases were collected")
    return data


# ── scanners ─────────────────────────────────────────────────────────────────


def pick_device(requested: str) -> str:
    if requested != "auto":
        return requested
    try:
        import torch  # noqa: PLC0415
        return "cuda" if torch.cuda.is_available() else "cpu"
    except ImportError:
        return "cpu"


class SemanticScorer:
    """The SDK's semantic scanner with one embedding backend, scored in batches."""

    def __init__(self, backend: str, device: str) -> None:
        import numpy as np  # noqa: PLC0415
        from acf.scanners import EmbeddingBackend, SemanticScanner, is_scannable  # noqa: PLC0415

        self.np, self.is_scannable = np, is_scannable
        started = time.perf_counter()
        if backend == "tfidf":
            self.scanner = SemanticScanner(backend="tfidf")
        elif backend == "minilm":
            self.scanner = SemanticScanner(backend="sentence-transformer")
            self.scanner._backend._model.to(device)
        else:
            self.scanner = SemanticScanner(backend=_gemma_backend(EmbeddingBackend, np, device))
        self.load_s = round(time.perf_counter() - started, 1)
        self.threshold = self.scanner._config.default_threshold

    def _calibrated(self, texts: list[str]) -> list[float]:
        """The scanner's risk_score for each text, as SemanticScanner.scan computes it."""
        scores = [0.0] * len(texts)
        keep = [i for i, text in enumerate(texts) if self.is_scannable(text)]
        if keep:
            vectors = self.scanner._backend.encode([texts[i] for i in keep])
            raw = vectors @ self.scanner._embeddings.T
            calibration = self.scanner._calibration
            for row, i in zip(raw, keep):
                scores[i] = max(float(self.np.max(calibration.to_score(calibration.z_scores(row)))), 0.0)
        return scores

    def score(self, rows: list[dict[str, Any]], mode: str) -> list[float]:
        texts = [row["text"] for row in rows]
        if mode == "whole":
            return self._calibrated(texts)
        pieces, owner = [], []
        for i, text in enumerate(texts):
            for piece in windows(text):
                pieces.append(piece)
                owner.append(i)
        out = [0.0] * len(texts)
        for value, i in zip(self._calibrated(pieces), owner):
            out[i] = max(out[i], value)
        return out

    def time_one(self, text: str) -> None:
        self.scanner._backend.encode_single(text)

    def close(self) -> None:
        return None


def _gemma_backend(base: type, np: Any, device: str) -> Any:
    import torch  # noqa: PLC0415
    from sentence_transformers import SentenceTransformer  # noqa: PLC0415

    # bfloat16 where the hardware supports it; float32 elsewhere. float16 gives NaNs.
    dtype = torch.bfloat16 if device.startswith("cuda") and torch.cuda.is_bf16_supported() else torch.float32

    class GemmaBackend(base):
        """EmbeddingGemma 2 with the vision and audio encoders left out."""

        def __init__(self) -> None:
            self.model = SentenceTransformer(
                GEMMA_MODEL, device=device,
                config_kwargs={"vision_config": None, "audio_config": None},
                model_kwargs={"torch_dtype": dtype},
            )
            self.model.max_seq_length = WHOLE_MAX_TOKENS

        def encode(self, texts):
            return np.asarray(self.model.encode(
                list(texts), prompt_name="SentenceSimilarity", normalize_embeddings=True,
                show_progress_bar=False, batch_size=32 if device.startswith("cuda") else 8,
            ).astype("float32"), dtype=np.float64)

        def encode_single(self, text):
            return self.encode([text])[0]

    return GemmaBackend()


class LexicalScorer:
    """The sidecar's own verdict with the SDK's semantic scanner off.

    Scores are 1.0 for SANITISE or BLOCK and 0.0 for ALLOW, so the same
    threshold logic applies. Windows are not used: the sidecar scans the text
    it is given.
    """

    threshold = 0.5

    def __init__(self, binary: Path, work_dir: Path, build: bool) -> None:
        started = time.perf_counter()
        if build or not binary.exists():
            harness.build_sidecar(binary)
        factory = harness.FirewallFactory(None)
        self.pool = harness.SidecarPool(binary, work_dir, factory, name="scanners")
        # Tool calls are not made here, so the allowlist only has to satisfy preflight.
        self.firewall = factory.get(self.pool.socket_for(("ACFScannerCompare",)))
        self.load_s = round(time.perf_counter() - started, 1)

    def _verdict(self, row: dict[str, Any]) -> float:
        if row.get("tool"):
            result = self.firewall.on_tool_result(row["tool"], row["text"])
        else:
            result = self.firewall.on_prompt(row["text"])
        return 0.0 if harness.decision_of(result).name == "ALLOW" else 1.0

    def score(self, rows: list[dict[str, Any]], mode: str) -> list[float]:
        return [self._verdict(row) for row in rows]

    def time_one(self, text: str) -> None:
        self.firewall.on_tool_result("read_file", text)

    def close(self) -> None:
        self.pool.close()


def measure_latency(scorer: Any, texts: list[str], repeats: int = 9) -> dict[str, Any]:
    """Median ms for one whole-text call, at the 10th, 50th and 90th percentile of length."""
    by_length = sorted(texts, key=lambda t: len(t.split()))
    picks = {"short": by_length[len(by_length) // 10], "median": by_length[len(by_length) // 2],
             "long": by_length[int(len(by_length) * 0.9)]}
    result = {}
    for label, text in picks.items():
        scorer.time_one(text)  # warm up
        times = []
        for _ in range(repeats):
            started = time.perf_counter()
            scorer.time_one(text)
            times.append((time.perf_counter() - started) * 1000)
        result[label] = {"words": len(text.split()), "ms_p50": round(statistics.median(times), 2)}
    return result


# ── run ──────────────────────────────────────────────────────────────────────


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--backends", default="lexical,tfidf,gemma",
                        help=f"comma list of {', '.join(BACKENDS)}")
    parser.add_argument("--wordings", default=",".join(WORDINGS), help="AgentDojo attack names")
    parser.add_argument("--modes", default=",".join(MODES), help="whole, window, or both")
    parser.add_argument("--stride", type=int, default=1,
                        help="use every Nth replayable case (1 = all 609 per wording)")
    parser.add_argument("--device", default="auto", help="auto, cpu, cuda, cuda:0, ...")
    parser.add_argument("--benchmark-version", default="v1.2.2")
    parser.add_argument("--sidecar-binary", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--no-build-sidecar", action="store_true",
                        help="use the existing sidecar binary instead of rebuilding it")
    parser.add_argument("--results-dir", type=Path, default=DEFAULT_RESULTS_DIR)
    args = parser.parse_args(argv)
    args.backends = harness.csv_choices(args.backends, list(BACKENDS), "backends")
    args.modes = harness.csv_choices(args.modes, list(MODES), "modes")
    args.wordings = [w.strip() for w in args.wordings.split(",") if w.strip()]
    if args.stride < 1:
        raise SystemExit("--stride must be at least 1")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    harness.clear_sdk_env()
    import importlib.metadata  # noqa: PLC0415

    device = pick_device(args.device)
    out_dir = harness.new_output_dir(args.results_dir, "scanners")
    print(f"scanner comparison: backends={args.backends} modes={args.modes} stride={args.stride} "
          f"device={device}\ncollecting texts...", flush=True)
    data = collect_texts(args.benchmark_version, args.wordings, args.stride)
    groups = {"prompts": data["prompts"], "outputs": data["outputs"],
              **{f"attack:{w}": rows for w, rows in data["attack"].items()}}
    all_texts = [row["text"] for rows in groups.values() for row in rows]
    print(f"  benign: {len(data['prompts'])} user requests, {len(data['outputs'])} tool results",
          flush=True)

    summary: dict[str, Any] = {"backends": {}}
    scores_path = out_dir / "scores.jsonl"
    with scores_path.open("w", encoding="utf-8") as scores_file:
        for backend in args.backends:
            print(f"{backend}: loading...", flush=True)
            if backend == "lexical":
                scorer: Any = LexicalScorer(args.sidecar_binary, out_dir / "work",
                                            build=not args.no_build_sidecar)
                modes = ["whole"]
            else:
                scorer = SemanticScorer(backend, device)
                modes = args.modes
            try:
                entry: dict[str, Any] = {"load_s": scorer.load_s, "threshold": scorer.threshold,
                                         "latency": measure_latency(scorer, all_texts), "modes": {}}
                for mode in modes:
                    started = time.perf_counter()
                    scores = {}
                    for group, rows in groups.items():
                        scores[group] = scorer.score(rows, mode)
                        for row, value in zip(rows, scores[group]):
                            scores_file.write(json.dumps({
                                "backend": backend, "mode": mode, "group": group,
                                "id": row["id"], "score": round(value, 4)}) + "\n")
                    scores_file.flush()
                    entry["modes"][mode] = {**summarise(scores, scorer.threshold),
                                            "seconds": round(time.perf_counter() - started, 1)}
                    flagged = {w: a["flagged"] for w, a in entry["modes"][mode]["attack"].items()}
                    print(f"  {backend} {mode}: {flagged} "
                          f"benign requests {entry['modes'][mode]['prompts']['flagged']} "
                          f"({entry['modes'][mode]['seconds']}s)", flush=True)
                summary["backends"][backend] = entry
            finally:
                scorer.close()
            # Written after every backend, so a long run keeps what it has finished.
            summary["provenance"] = harness.provenance(
                Path(__file__), HERE / "manifest.json",
                args.sidecar_binary if "lexical" in args.backends else None,
                {
                    "agentdojo_version": importlib.metadata.version("agentdojo"),
                    "benchmark_version": args.benchmark_version,
                    "wordings": args.wordings,
                    "stride": args.stride,
                    "modes": args.modes,
                    "device": device,
                    "threshold": 0.5,
                    "window_words": WINDOW_WORDS,
                    "window_stride": WINDOW_STRIDE,
                    "whole_max_tokens": WHOLE_MAX_TOKENS,
                    "gemma_model": GEMMA_MODEL,
                    "packages": {name: _version(name) for name in
                                 ("torch", "sentence-transformers", "transformers", "scikit-learn", "numpy")},
                },
            )
            harness.write_summary(out_dir, summary, render_markdown(summary))
    print(f"results: {out_dir}")
    return 0


def _version(package: str) -> str | None:
    import importlib.metadata  # noqa: PLC0415
    try:
        return importlib.metadata.version(package)
    except importlib.metadata.PackageNotFoundError:
        return None


if __name__ == "__main__":
    raise SystemExit(main())

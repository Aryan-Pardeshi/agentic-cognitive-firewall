from __future__ import annotations

import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import scanner_compare as sc  # noqa: E402


def test_windows_cover_the_text_with_overlap():
    text = " ".join(str(i) for i in range(100))
    pieces = sc.windows(text, size=48, stride=24)
    assert pieces[0].split()[0] == "0" and pieces[-1].split()[-1] == "99"
    assert all(len(p.split()) <= 48 for p in pieces)
    # Consecutive windows share half their words, so a phrase is never split
    # across every window that contains part of it.
    assert pieces[1].split()[0] == "24"
    assert set(" ".join(pieces).split()) == set(text.split())


def test_short_text_is_one_window_unchanged():
    assert sc.windows("pay the  bill") == ["pay the  bill"]
    assert sc.windows(" ".join(["w"] * 48)) == [" ".join(["w"] * 48)]


def test_wilson_interval_brackets_the_rate():
    low, high = sc.wilson(107, 153)
    assert low < 107 / 153 < high and 0.62 < low < 0.64 and 0.76 < high < 0.78
    assert sc.wilson(0, 0) is None
    assert sc.wilson(0, 50)[0] == 0.0


def test_summarise_counts_at_the_threshold_and_at_zero_false_positives():
    scores = {
        "prompts": [0.1, 0.6, 0.2],
        "outputs": [0.0, 0.4],
        "attack:injecagent": [0.9, 0.55, 0.3, 0.7],
        "attack:direct": [0.1, 0.1],
    }
    out = sc.summarise(scores, threshold=0.5)
    assert out["prompts"] == {"n": 3, "flagged": 1} and out["outputs"] == {"n": 2, "flagged": 0}
    assert out["benign_max"] == 0.6
    inj = out["attack"]["injecagent"]
    assert inj["flagged"] == 3 and inj["rate"] == 0.75
    # Only the scores above the highest benign score (0.6) survive a zero-FP threshold.
    assert inj["flagged_at_zero_fp"] == 2
    assert out["attack"]["direct"]["flagged"] == 0 and out["attack"]["direct"]["ci95"][0] == 0.0


def test_render_markdown_lists_each_scanner_and_mode():
    modes = {"whole": {**sc.summarise({"prompts": [0.0], "outputs": [0.0],
                                       "attack:injecagent": [1.0, 1.0]}, 0.5), "seconds": 0.1}}
    summary = {
        "provenance": {"agentdojo_version": "0.1.35", "benchmark_version": "v1.2.2", "stride": 1,
                       "threshold": 0.5, "device": "cpu", "acf_commit": "abc",
                       "wordings": ["injecagent", "direct"]},
        "backends": {"lexical": {"load_s": 1.0, "modes": modes,
                                 "latency": {"short": {"words": 5, "ms_p50": 0.3}}}},
    }
    text = sc.render_markdown(summary)
    assert "| lexical | whole | 2/2 (100.0%) | n/a |" in text
    assert "not ACF's final decision" in text and "0.3 ms (5 words)" in text


def test_parse_args_defaults_to_every_case_and_rejects_unknown_scanners():
    args = sc.parse_args([])
    assert args.stride == 1 and args.backends == ["lexical", "tfidf", "gemma"]
    assert args.modes == ["whole", "window"] and len(args.wordings) == 6
    with pytest.raises(SystemExit):
        sc.parse_args(["--backends", "bert"])
    with pytest.raises(SystemExit):
        sc.parse_args(["--stride", "0"])

"""
Start a sidecar with ACF's shared rules and this application's policy data.

ACF splits policy into logic and data. The Rego rules in policies/v1 are the
same for every deployment; an application supplies the data they read. This
script builds that combination for the banking examples:

  1. copies policies/v1 to examples/banking/.policy/
  2. merges examples/banking/policy.yaml over its data/policy_config.yaml
  3. writes a sidecar.yaml that uses that policy directory and allowlist
  4. starts the sidecar with it

Usage (ACF_HMAC_KEY must be set, as for every example):

    python examples/banking/run_sidecar.py                 # uses `go run`
    python examples/banking/run_sidecar.py --binary PATH   # a built sidecar

Leave it running, and run the banking examples from another terminal.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
BUILD = HERE / ".policy"


def read_overlay(path: Path) -> dict[str, str]:
    """Top-level `key: value` lines of policy.yaml, with the value kept as text.

    Values are one-line YAML flow style, so they can be copied into the
    shipped file verbatim. This keeps the example free of a YAML dependency.
    """
    overlay: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#") or line[0].isspace():
            continue
        key, sep, value = line.partition(":")
        if not sep or not value.strip():
            raise SystemExit(f"{path.name}: expected `key: value` on one line, got {line!r}")
        overlay[key.strip()] = value.split(" #")[0].strip()
    return overlay


def set_top_level(text: str, key: str, value: str) -> str:
    """Replace a top-level key, with any lines indented under it, by `key: value`."""
    pattern = re.compile(rf"^{re.escape(key)}:[^\n]*(?:\n[ \t]+[^\n]*)*", re.MULTILINE)
    updated, count = pattern.subn(lambda _: f"{key}: {value}", text, count=1)
    if count == 0:
        updated = text.rstrip("\n") + f"\n{key}: {value}\n"
    return updated


def build() -> Path:
    overlay = read_overlay(HERE / "policy.yaml")
    if BUILD.exists():
        shutil.rmtree(BUILD)
    shutil.copytree(REPO / "policies" / "v1", BUILD / "policies")

    data = BUILD / "policies" / "data" / "policy_config.yaml"
    text = data.read_text(encoding="utf-8")
    for key, value in overlay.items():
        text = set_top_level(text, key, value)
    data.write_text(text, encoding="utf-8")

    # The sidecar's own scan stage also checks the allowlist, so both files
    # carry it. Paths are absolute so the sidecar can start from any directory.
    config = (REPO / "config" / "sidecar.yaml").read_text(encoding="utf-8")
    config = set_top_level(config, "policy_dir", json.dumps(str(BUILD / "policies")))
    if "tool_allowlist" in overlay:
        config = set_top_level(config, "tool_allowlist", overlay["tool_allowlist"])
    sidecar_yaml = BUILD / "sidecar.yaml"
    sidecar_yaml.write_text(config, encoding="utf-8")
    return sidecar_yaml


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--binary", type=Path, help="a built sidecar; default: go run ./cmd/sidecar")
    parser.add_argument("--build-only", action="store_true", help="write .policy/ and exit")
    args = parser.parse_args()

    sidecar_yaml = build()
    print(f"policy: shared rules from policies/v1 + data from {HERE.name}/policy.yaml")
    print(f"config: {sidecar_yaml}")
    if args.build_only:
        return 0
    if not os.environ.get("ACF_HMAC_KEY"):
        print("ACF_HMAC_KEY is not set; see examples/README.md", file=sys.stderr)
        return 1

    env = dict(os.environ, ACF_CONFIG=str(sidecar_yaml))
    command = [str(args.binary.resolve())] if args.binary else ["go", "run", "./cmd/sidecar"]
    try:
        return subprocess.call(command, cwd=REPO / "sidecar", env=env)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())

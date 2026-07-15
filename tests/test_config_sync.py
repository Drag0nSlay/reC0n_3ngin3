"""
tests/test_config_sync.py

Guards against the exact class of bug that kept recurring during
development: config/settings.example.yaml silently drifting out of
sync with config/settings.yaml every time a new section/key was added
to one but not the other (enumeration:, extra_args:, org_name, awscli
path all slipped through this way at various points).

This does NOT compare values (settings.yaml has real config, the
example has placeholders) — only that every KEY PATH present in one
file also exists in the other. Run manually or wire into CI:

    python -m tests.test_config_sync
"""

from __future__ import annotations
import sys
import yaml


def _collect_key_paths(d: dict, prefix: str = "") -> set:
    """Flattens a nested dict into a set of dotted key paths, e.g.
    {"a": {"b": 1}} -> {"a", "a.b"}. Lists are treated as leaves (their
    contents/length legitimately differ between real and example
    configs, e.g. permutation_terms), not recursed into."""
    paths = set()
    for key, value in d.items():
        full_key = f"{prefix}.{key}" if prefix else key
        paths.add(full_key)
        if isinstance(value, dict):
            paths |= _collect_key_paths(value, full_key)
    return paths


def check_sync(real_path: str = "config/settings.yaml",
                example_path: str = "config/settings.example.yaml") -> list[str]:
    with open(real_path) as f:
        real = yaml.safe_load(f)
    with open(example_path) as f:
        example = yaml.safe_load(f)

    real_keys = _collect_key_paths(real)
    example_keys = _collect_key_paths(example)

    missing_from_example = sorted(real_keys - example_keys)
    missing_from_real = sorted(example_keys - real_keys)

    problems = []
    for k in missing_from_example:
        problems.append(f"'{k}' exists in {real_path} but NOT in {example_path}")
    for k in missing_from_real:
        problems.append(f"'{k}' exists in {example_path} but NOT in {real_path}")

    return problems


def main():
    problems = check_sync()
    if problems:
        print(f"❌ CONFIG DRIFT DETECTED — {len(problems)} issue(s):")
        for p in problems:
            print(f"  - {p}")
        sys.exit(1)
    else:
        print("✅ settings.yaml and settings.example.yaml are structurally in sync")
        sys.exit(0)


if __name__ == "__main__":
    main()

"""
utils/dedupe.py
Deduplication helpers used at every stage of the pipeline
(principle #2 in the core architecture: "Deduplicate at every stage").

Handles:
  - plain string/line dedupe (subdomains, IPs, URLs)
  - normalization (lowercase, strip trailing dot, strip scheme for domains)
  - persistent "seen" sets so re-runs don't reprocess old data
"""

from __future__ import annotations
import json
import os
from typing import Iterable, Set


def normalize_domain(d: str) -> str:
    d = d.strip().lower()
    d = d.rstrip(".")
    for prefix in ("http://", "https://"):
        if d.startswith(prefix):
            d = d[len(prefix):]
    d = d.split("/")[0]  # drop path if a full URL slipped in
    return d


def dedupe_lines(lines: Iterable[str], normalize=True) -> Set[str]:
    out: Set[str] = set()
    for line in lines:
        if not line:
            continue
        line = line.strip()
        if not line:
            continue
        out.add(normalize_domain(line) if normalize else line)
    return out


def load_set(path: str) -> Set[str]:
    if not os.path.exists(path):
        return set()
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return dedupe_lines(f.readlines())


def save_set(path: str, data: Set[str]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for item in sorted(data):
            f.write(item + "\n")


def merge_and_dedupe(*paths_or_sets, output_path: str | None = None) -> Set[str]:
    """Merge any mix of file paths and in-memory sets, dedupe, optionally persist."""
    merged: Set[str] = set()
    for item in paths_or_sets:
        if isinstance(item, str):
            merged |= load_set(item)
        else:
            merged |= dedupe_lines(item)
    if output_path:
        save_set(output_path, merged)
    return merged


class SeenStore:
    """
    Tracks items already discovered across runs so repeated scans
    only report *new* findings (diffing), stored as JSON on disk.
    """

    def __init__(self, path: str):
        self.path = path
        self._seen: Set[str] = set()
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                self._seen = set(json.load(f))

    def diff_new(self, items: Iterable[str]) -> Set[str]:
        items = set(items)
        new = items - self._seen
        self._seen |= items
        return new

    def persist(self) -> None:
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(sorted(self._seen), f, indent=2)

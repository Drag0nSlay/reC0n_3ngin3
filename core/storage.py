"""
core/storage.py

Phase 12 — Data Handling.
SQLite-backed storage (simple, zero-setup, matches this project's
"store everything, reuse later" core principle). Swap for MongoDB later
by re-implementing this same interface if you outgrow SQLite — nothing
else in the pipeline should need to change if you keep the method
signatures.

Schema:
  runs         — one row per pipeline execution (timestamped)
  subdomains   — domain, first_seen_run, last_seen_run
  ips          — ip, first_seen_run, last_seen_run
  ports        — host, port, first_seen_run, last_seen_run
  urls         — url, first_seen_run, last_seen_run
  findings     — category (secret/nuclei/takeover/bucket/...), detail,
                 source_url, run_id, discovered_at

Diffing: save_* methods return the subset of items never seen in any
prior run, so repeated scans surface *changes*, not the same output
every time.
"""

from __future__ import annotations
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterable, Set

from utils.logger import get_logger

log = get_logger("core.storage")

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    started_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS subdomains (
    domain TEXT PRIMARY KEY,
    first_seen_run INTEGER NOT NULL,
    last_seen_run INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS ips (
    ip TEXT PRIMARY KEY,
    first_seen_run INTEGER NOT NULL,
    last_seen_run INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS ports (
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    first_seen_run INTEGER NOT NULL,
    last_seen_run INTEGER NOT NULL,
    PRIMARY KEY (host, port)
);

CREATE TABLE IF NOT EXISTS urls (
    url TEXT PRIMARY KEY,
    first_seen_run INTEGER NOT NULL,
    last_seen_run INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL,
    category TEXT NOT NULL,
    detail TEXT NOT NULL,
    source_url TEXT,
    discovered_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);
"""


class Storage:
    def __init__(self, db_path: str):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        self._conn = sqlite3.connect(db_path)
        self._conn.executescript(SCHEMA)
        self._conn.commit()
        self.run_id: int | None = None

    @contextmanager
    def _cursor(self):
        cur = self._conn.cursor()
        try:
            yield cur
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise
        finally:
            cur.close()

    def start_run(self, target: str) -> int:
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO runs (target, started_at) VALUES (?, ?)",
                (target, datetime.now(timezone.utc).isoformat()),
            )
            self.run_id = cur.lastrowid
        log.info(f"Storage: started run #{self.run_id} for {target}")
        return self.run_id

    def _upsert_seen(self, table: str, key_col: str, key: str) -> None:
        assert self.run_id is not None, "call start_run() first"
        with self._cursor() as cur:
            cur.execute(
                f"""
                INSERT INTO {table} ({key_col}, first_seen_run, last_seen_run)
                VALUES (?, ?, ?)
                ON CONFLICT({key_col}) DO UPDATE SET last_seen_run = excluded.last_seen_run
                """,
                (key, self.run_id, self.run_id),
            )

    def save_subdomains(self, domains: Iterable[str]) -> Set[str]:
        domains = list(domains)
        with self._cursor() as cur:
            cur.execute("SELECT domain FROM subdomains")
            previously_seen = {row[0] for row in cur.fetchall()}
        new = set(domains) - previously_seen
        for d in domains:
            self._upsert_seen("subdomains", "domain", d)
        log.info(f"Storage: {len(new)} new subdomains this run ({len(domains)} total input)")
        return new

    def save_ips(self, ips: Iterable[str]) -> Set[str]:
        ips = list(ips)
        with self._cursor() as cur:
            cur.execute("SELECT ip FROM ips")
            previously_seen = {row[0] for row in cur.fetchall()}
        new = set(ips) - previously_seen
        for ip in ips:
            self._upsert_seen("ips", "ip", ip)
        return new

    def save_ports(self, host_port_pairs: Iterable[str]) -> Set[str]:
        """host_port_pairs: 'host:port' strings."""
        pairs = list(host_port_pairs)
        with self._cursor() as cur:
            cur.execute("SELECT host, port FROM ports")
            previously_seen = {f"{h}:{p}" for h, p in cur.fetchall()}
        new = set(pairs) - previously_seen
        assert self.run_id is not None, "call start_run() first"
        for pair in pairs:
            if ":" not in pair:
                continue
            host, _, port = pair.rpartition(":")
            if not port.isdigit():
                continue
            with self._cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO ports (host, port, first_seen_run, last_seen_run)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(host, port) DO UPDATE SET last_seen_run = excluded.last_seen_run
                    """,
                    (host, int(port), self.run_id, self.run_id),
                )
        return new

    def save_urls(self, urls: Iterable[str]) -> Set[str]:
        urls = list(urls)
        with self._cursor() as cur:
            cur.execute("SELECT url FROM urls")
            previously_seen = {row[0] for row in cur.fetchall()}
        new = set(urls) - previously_seen
        for u in urls:
            self._upsert_seen("urls", "url", u)
        return new

    def save_finding(self, category: str, detail: str, source_url: str | None = None) -> None:
        assert self.run_id is not None, "call start_run() first"
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO findings (run_id, category, detail, source_url, discovered_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (self.run_id, category, detail, source_url, datetime.now(timezone.utc).isoformat()),
            )

    def save_findings_bulk(self, category: str, details: Iterable[str]) -> None:
        for d in details:
            self.save_finding(category, d)

    def diff_new(self, table: str, key_col: str, current_items: Iterable[str]) -> Set[str]:
        """Generic helper: what in current_items has never been seen in `table` before."""
        with self._cursor() as cur:
            cur.execute(f"SELECT {key_col} FROM {table}")
            previously_seen = {row[0] for row in cur.fetchall()}
        return set(current_items) - previously_seen

    def close(self) -> None:
        self._conn.close()

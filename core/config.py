"""
core/config.py
Loads config/settings.yaml once and exposes it as a simple object.
"""

from __future__ import annotations
import re
import yaml
import os


def _sanitize_for_path(domain: str) -> str:
    """Filesystem-safe folder name for a domain (dots/hyphens are fine on
    every OS we care about; this just guards against anything unexpected
    like spaces or slashes ending up in target.domain)."""
    return re.sub(r"[^a-zA-Z0-9.\-]", "_", domain)


class Config:
    def __init__(self, path: str = "config/settings.yaml"):
        if not os.path.exists(path):
            raise FileNotFoundError(f"Config not found: {path}")
        with open(path, "r", encoding="utf-8") as f:
            self._raw = yaml.safe_load(f)

    @property
    def domain(self) -> str:
        return self._raw["target"]["domain"]

    @property
    def org_name(self) -> str:
        """Optional — used by amass intel -org for organization-wide
        ASN/netblock discovery. Falls back to a guess derived from the
        domain if not set (weaker signal)."""
        return self._raw["target"].get("org_name", "") or ""

    @property
    def authorized(self) -> bool:
        return bool(self._raw["target"].get("authorized", False))

    def api_key(self, name: str) -> str:
        return self._raw.get("api_keys", {}).get(name, "") or ""

    def tool_path(self, name: str) -> str:
        return self._raw.get("paths", {}).get(name, name)

    def extra_args(self, name: str) -> list:
        """
        User-supplied extra CLI flags for a given tool, appended after
        this pipeline's own default args. Escape hatch for the many
        tool-specific subcommands/flags (nmap --script, nuclei -tags,
        subfinder -recursive, ffuf -mc, etc.) this project doesn't wire
        up individually. Configure under extra_args: in settings.yaml.

        You are responsible for anything you add here staying within
        your authorized scope — this bypasses none of the existing
        target.authorized gates, it only adds flags to calls that would
        already run.
        """
        val = self._raw.get("extra_args", {}).get(name, [])
        return list(val) if val else []

    @property
    def max_workers(self) -> int:
        return int(self._raw.get("concurrency", {}).get("max_workers", 8))

    @property
    def http_timeout(self) -> int:
        return int(self._raw.get("concurrency", {}).get("http_timeout", 15))

    @property
    def raw_dir(self) -> str:
        """Domain-scoped: data/raw/<domain>/ — running a different
        target.domain never overwrites another domain's output."""
        base = self._raw["output"]["raw_dir"]
        return os.path.join(base, _sanitize_for_path(self.domain))

    @property
    def processed_dir(self) -> str:
        """Domain-scoped: data/processed/<domain>/ — same reasoning as raw_dir."""
        base = self._raw["output"]["processed_dir"]
        return os.path.join(base, _sanitize_for_path(self.domain))

    @property
    def db_path(self) -> str:
        """
        Intentionally NOT domain-scoped — recon.sqlite3 is meant to be a
        single shared, cross-run history store (Phase 12: "reuse data,
        diff scans later"). This stays safe across domains because every
        table's primary key (a subdomain string, a host:port pair, a
        full URL) is inherently domain-specific text — "api.a.com" and
        "api.b.com" can never collide. If you want fully isolated
        per-domain databases instead, point output.db_path at a
        domain-specific file yourself in settings.yaml.
        """
        return self._raw["output"].get("db_path", "data/processed/recon.sqlite3")

    @property
    def naabu_top_ports(self) -> int:
        return int(self._raw.get("scan", {}).get("naabu_top_ports", 1000))

    @property
    def nmap_max_high_value_hosts(self) -> int:
        return int(self._raw.get("scan", {}).get("nmap_max_high_value_hosts", 50))

    @property
    def nuclei_severity(self) -> str:
        return self._raw.get("scan", {}).get("nuclei_severity", "info,low")

    @property
    def nuclei_exclude_tags(self) -> str:
        return self._raw.get("scan", {}).get("nuclei_exclude_tags", "dos,fuzz,intrusive")

    @property
    def permutation_terms(self) -> list:
        return self._raw.get("enumeration", {}).get("permutation_terms", [])

    @property
    def permutation_max_candidates(self) -> int:
        return int(self._raw.get("enumeration", {}).get("permutation_max_candidates", 3000))

    @property
    def recursion_keywords(self) -> list:
        return self._raw.get("enumeration", {}).get("recursion_keywords", [])

    @property
    def recursion_max_subroots(self) -> int:
        return int(self._raw.get("enumeration", {}).get("recursion_max_subroots", 10))

    @property
    def log_level(self) -> str:
        return self._raw.get("logging", {}).get("level", "INFO")

    @property
    def log_file(self) -> str:
        return self._raw.get("logging", {}).get("file", "data/recon.log")

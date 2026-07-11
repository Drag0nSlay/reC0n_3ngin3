"""
core/config.py
Loads config/settings.yaml once and exposes it as a simple object.
"""

from __future__ import annotations
import yaml
import os


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
    def authorized(self) -> bool:
        return bool(self._raw["target"].get("authorized", False))

    def api_key(self, name: str) -> str:
        return self._raw.get("api_keys", {}).get(name, "") or ""

    def tool_path(self, name: str) -> str:
        return self._raw.get("paths", {}).get(name, name)

    @property
    def max_workers(self) -> int:
        return int(self._raw.get("concurrency", {}).get("max_workers", 8))

    @property
    def http_timeout(self) -> int:
        return int(self._raw.get("concurrency", {}).get("http_timeout", 15))

    @property
    def raw_dir(self) -> str:
        return self._raw["output"]["raw_dir"]

    @property
    def processed_dir(self) -> str:
        return self._raw["output"]["processed_dir"]

    @property
    def db_path(self) -> str:
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
    def log_level(self) -> str:
        return self._raw.get("logging", {}).get("level", "INFO")

    @property
    def log_file(self) -> str:
        return self._raw.get("logging", {}).get("file", "data/recon.log")
